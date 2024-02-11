//
// Created by jason4_lee on 2020-09-28.
//

#include <cstdint>
#include <cstring>
#include <v4_operand2.h>

#ifndef GGADV2_MEM_API_H
#define GGADV2_MEM_API_H

namespace gg_core::gg_cpu {
template<bool U>
void calculateTargetAddr(uint32_t &targetAddr, unsigned offset) {
  if constexpr (U)
	targetAddr += offset;
  else
	targetAddr -= offset;
} // calculateTargetAddr()

template<typename T, bool SIGNED>
static void MemLoad(CPU &instance, uint32_t targetAddr, unsigned targetRegNum) {
  uint32_t &dst = instance._regs[targetRegNum];
  uint32_t &cycleCounter = instance._mem._elapsedCycle;

  /* 2nd cycle */
  if constexpr (sizeof(T) == 1) {
	if constexpr (SIGNED) {
	  // LDRSB, sign extend
	  int8_t byteResult = instance._mem.Read<uint8_t>(targetAddr, gg_mem::N_Cycle);
	  dst = (unsigned)byteResult;
	} // if
	else // LDRB
	  dst = instance._mem.Read<uint8_t>(targetAddr, gg_mem::N_Cycle);
  } // if
  else if constexpr (sizeof(T) == 2) {
	/**
	 * Mis-aligned LDRH,LDRSH (does or does not do strange things)
	 * On ARM7 aka ARMv4 aka NDS7/GBA:
	 * LDRH Rd,[odd]   -->  LDRH Rd,[odd-1] ROR 8  ;read to bit0-7 and bit24-31
	 * LDRSH Rd,[odd]  -->  LDRSB Rd,[odd]         ;sign-expand BYTE value
	 **/
	const bool misAligned = targetAddr & 1;
	if constexpr (SIGNED) {
	  // LDRSH
	  int16_t wordResult = instance._mem.Read<uint16_t>(targetAddr, gg_mem::N_Cycle);
	  dst = (unsigned)(wordResult);
	} // if constexpr
	else {
	  // LDRH
	  dst = instance._mem.Read<uint16_t>(targetAddr, gg_mem::N_Cycle);
	} // else
  } // else if
  else {
	// LDR
	dst = instance._mem.Read<uint32_t>(targetAddr, gg_mem::N_Cycle);
  } // else

  instance.Idle();
  if (targetRegNum == pc) {
	instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);
  } // if
} // LDR()

template<typename T>
static void MemStore(CPU &instance, uint32_t targetAddr, unsigned targetRegNum) {
  uint32_t &src = instance._regs[targetRegNum];

  if (targetRegNum == pc) // ARM mode only, impossible for Thumb
	instance._mem.Write<T>(targetAddr, static_cast<T>(src + 4), gg_mem::N_Cycle);
  else
	instance._mem.Write<T>(targetAddr, static_cast<T>(src), gg_mem::N_Cycle);
} // MemStore()

template <bool P, bool U>
static uint32_t CalculatePushPopStart(const uint32_t baseAddr, const uint32_t offset) {
  if constexpr (U) {
	if constexpr (P) {
	  // pre-increment
	  return baseAddr + 4;
	} // if
	else {
	  // post-increment
	  return baseAddr;
	} // else
  } // if
  else {
	if constexpr (P) {
	  // pre-decrement
	  return baseAddr - offset;
	} // if
	else {
	  // post-decrement
	  return baseAddr - offset + 4;
	} // else
  } // else
} // CalculatePushPopStart()

template <bool U>
static uint32_t CalculatePushPopEnd(const uint32_t startAddr, const uint32_t offset) {
  if constexpr (U)
	return startAddr + offset;
  else
	return startAddr - offset;
} // CalculatePushPopEnd()


template<bool L, bool P, bool U, bool W>
static void PushPop(CPU &instance, const unsigned baseRegIdx, const unsigned regList, const uint32_t offset) {
  unsigned registerCnt = PopCount32(regList);

  uint32_t baseAddr = instance._regs[baseRegIdx] & ~0x3;
  const unsigned instructionLength = instance.instructionLength;
  const uint32_t accessStartAddr = CalculatePushPopStart<P, U>(baseAddr, offset);
  auto &mem = instance._mem;
  bool needRefillPipeline = false;

  uint32_t readPtr = accessStartAddr;
  uint32_t originalPC = instance._regs[pc];

  if constexpr (W) {
	instance._regs[baseRegIdx] = CalculatePushPopEnd<U>(baseAddr, offset);
  } // if

  gg_mem::E_AccessType cycleType = gg_mem::N_Cycle;
  for (int i = 0 ; i < 16 ; ++i) {
	const bool regInList = TestBit(regList, i);
	if (regInList) {
	  if constexpr (L) {
		instance._regs[i] = mem.Read<uint32_t>(readPtr, cycleType);
	  } // if constexpr
	  else {
		uint32_t regValue = instance._regs[i];
		if (i == pc)
		  regValue += instructionLength;
		mem.Write<uint32_t>(readPtr, regValue, cycleType);
	  } // else

	  readPtr += 4;
	  --registerCnt;
	  cycleType = gg_mem::S_Cycle;
	} // if
  } // for

  if constexpr (L) {
	instance.Idle();
	if (instance._regs[pc] != originalPC) {
	  // pc is modified, need to refill pipeline
	  instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);
	} // if
  } // if constexpr
} // PushPop()

template<bool I, bool P, bool U, bool B, bool W, bool L, SHIFT_BY SHIFT_SRC, E_ShiftType ST>
static void SingleDataTransfer_impl(CPU &instance) {
  constexpr bool translation = !P && W;

  uint8_t RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16;
  uint8_t RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12;

  auto Access = [&]() {
	uint32_t &Rn = instance._regs[RnNumber];
	uint32_t &Rd = instance._regs[RdNumber];
	uint32_t offset = 0, targetAddr = Rn;

	if constexpr (I) {
	  const unsigned RmNumber = CURRENT_INSTRUCTION & 0xf;
	  unsigned shiftAmount;
	  bool shiftCarry = instance.C();

	  if constexpr (SHIFT_SRC == SHIFT_BY::IMM) {
		shiftAmount = gg_core::BitFieldValue<7, 5>(CURRENT_INSTRUCTION);
	  } // if constexpr
	  else {
		const unsigned RsNumber = gg_core::BitFieldValue<8, 4>(CURRENT_INSTRUCTION);
		shiftAmount = instance._regs[RsNumber];
	  } // else

	  ALU_CalculateShiftOp2<SHIFT_SRC, ST>(instance, RmNumber, shiftAmount, offset, shiftCarry);
	} // constexpr()
	else {
	  offset = CURRENT_INSTRUCTION & 0xfff;
	} // else

	if constexpr (L) {
	  // ldr
	  if constexpr (P)
		calculateTargetAddr<U>(targetAddr, offset);

	  if constexpr (B)
		MemLoad<uint8_t, false>(instance, targetAddr, RdNumber);
	  else
		MemLoad<uint32_t, false>(instance, targetAddr, RdNumber);

	  if constexpr (!P || W) {
		// Info from heyrick.eu:
		//      Pre-indexed (any) / Post-indexed (any): Using the same register as Rd and Rn is unpredictable.
		if (RnNumber != RdNumber) {
		  if constexpr (!P)
			calculateTargetAddr<U>(targetAddr, offset);
		  Rn = targetAddr;
		} // if
	  } // if
	} // if
	else {
	  // str
	  if constexpr (P)
		calculateTargetAddr<U>(targetAddr, offset);

	  if constexpr (B)
		MemStore<uint8_t>(instance, targetAddr, RdNumber);
	  else
		MemStore<uint32_t>(instance, targetAddr, RdNumber);

	  if constexpr (!P || W) {
		// Info from heyrick.eu:
		//      Pre-indexed (any) / Post-indexed (any): Using the same register as Rd and Rn is unpredictable.
		if constexpr (!P)
		  calculateTargetAddr<U>(targetAddr, offset);
		Rn = targetAddr;
	  } // if
	} // else
  };

  if constexpr (translation)
	instance.AccessUsrRegBankInPrivilege(Access);
  else
	Access();
} // MemAccess_impl()

template<bool P, bool U, bool W, bool L, bool S, bool H, OFFSET_TYPE OT>
void HalfMemAccess_impl(CPU &instance) {
  unsigned int RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16;
  unsigned int RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12;
  uint32_t &Rn = instance._regs[RnNumber];
  uint32_t &Rd = instance._regs[RdNumber];
  uint32_t offset = 0, targetAddr = Rn;

  if constexpr (OT == OFFSET_TYPE::RM) {
	offset = instance._regs[CURRENT_INSTRUCTION & 0xf];
  } // constexpr()
  else {
	offset = ((CURRENT_INSTRUCTION & 0xf00) >> 4) | (CURRENT_INSTRUCTION & 0xf);
  } // else

  if constexpr (L) {
	// ldr
	if constexpr (P)
	  calculateTargetAddr<U>(targetAddr, offset);

	if constexpr (H)
	  MemLoad<uint16_t, S>(instance, targetAddr, RdNumber);
	else
	  MemLoad<uint8_t, S>(instance, targetAddr, RdNumber);

	if constexpr (!P || W) {
	  if constexpr (!P)
		calculateTargetAddr<U>(targetAddr, offset);
	  if (RdNumber != RnNumber)
		Rn = targetAddr;
	} // if
  } // if
  else {
	// str
	if constexpr (P)
	  calculateTargetAddr<U>(targetAddr, offset);

	/*
	 * Move compile time tag check to decoder
	 */

	MemStore<uint16_t>(instance, targetAddr, RdNumber);

	if constexpr (!P || W) {
	  if constexpr (!P)
		calculateTargetAddr<U>(targetAddr, offset);
	  Rn = targetAddr;
	} // if
  } // else
} // HalfMemAccess_impl()

template<bool P, bool U, bool S, bool W, bool L>
void BlockMemAccess_impl(CPU &instance) {
  // todo: undocumented behavior of ldm/stm implement
  uint32_t regList = BitFieldValue<0, 16>(CURRENT_INSTRUCTION);
  uint32_t offset = 0;
  uint32_t RnNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION);

  uint32_t currentCPSR = instance.ReadCPSR();
  uint32_t currentOpMode = instance.GetOperationMode();

  if constexpr (S) {
	if constexpr (L) {
	  if (TestBit(regList, 15)) {
		// LDM with R15 in transfer list and S bit set (Mode changes)
		// Do nothing here, CPSR will be changed after r15 is written......
	  } // if
	  else {
		// LDM without R15 in transfer list and S bit set (User bank transfer)
		instance.WriteCPSR((currentCPSR & ~0b11111) | static_cast<uint32_t>(E_OperationMode::USR));
	  } // else
	} // if constexpr
	else {
	  // STM with S bit set (User bank transfer)
	  instance.WriteCPSR((currentCPSR & ~0b11111) | static_cast<uint32_t>(E_OperationMode::USR));
	} // else
  } // if constexpr

  if (regList == 0) {
	regList = 0x8000; // pc only
	offset = 0x40;
  } // if
  else
	offset = PopCount32(regList) << 2;

  PushPop<L, P, U, W>(instance, RnNumber, regList, offset);

  if constexpr (S) {
	if constexpr (L) {
	  if (TestBit(regList, 15)) {
		// LDM with R15 in transfer list and S bit set (Mode changes)
		// ......Transfer the SPSR_<mode> to the CPSR
		instance.WriteCPSR(instance.ReadSPSR(static_cast<E_OperationMode>(currentOpMode)));
	  } // if
	} // if
	else {
	  // STM with r15 in transfer list and S bit set OR LDM without r15 in transfer list and S bit set
	  // (change the register bank back to the original mode)
	  instance.WriteCPSR((currentCPSR & ~0b11111) | currentOpMode);
	} // else
  } // if
} // BlockMemAccess_impl()

template<bool B>
void Swap_impl(CPU &instance) {
  uint32_t Rn = instance._regs[(CURRENT_INSTRUCTION & 0xf'0000) >> 16];
  uint32_t &Rd = instance._regs[(CURRENT_INSTRUCTION & 0x0'f000) >> 12];
  uint32_t Rm = instance._regs[CURRENT_INSTRUCTION & 0xf];

  if constexpr (B) {
	Rd = instance._mem.Read<uint8_t>(Rn, gg_mem::N_Cycle);
	instance._mem.Write<uint8_t>(Rn, (uint8_t)Rm, gg_mem::N_Cycle);
  } // if
  else {
	Rd = instance._mem.Read<uint32_t>(Rn, gg_mem::N_Cycle);
	instance._mem.Write<uint32_t>(Rn, Rm, gg_mem::N_Cycle);
  } // if

  instance.Idle();
} // Swap_impl()
}

#endif //GGADV2_MEM_API_H

//
// Created by jason4_lee on 2020-10-06.
//

#include <bit_manipulate.h>

#ifndef ARM_ANALYZER_V4_MULTIPLY_API_H
#define ARM_ANALYZER_V4_MULTIPLY_API_H

namespace gg_core::gg_cpu {
static int SignedBoothCheck(const unsigned op) {
  const int boothNum = (__builtin_clrsb(op) + 1) >> 3; // Number of leading 0 or 1 in arg2
  int m = boothNum == 4 ? 1 : 4 - boothNum;
  return m;
} // BoothCheck()

static int UnsignedBoothCheck(const unsigned op) {
  const int boothNum = __builtin_clz(op) >> 3; // Number of leading 0 or 1 in arg2
  int m = boothNum == 4 ? 1 : 4 - boothNum;
  return m;
} // BoothCheck()

template<bool S>
static uint32_t DoMultiply(CPU &instance, uint32_t arg1, uint32_t arg2) {
  int m = SignedBoothCheck(arg2);

  uint32_t result = arg1 * arg2;

//  instance.AddCycle(m, "Multiply I cycle");
  instance.Idle(m);
  return result;
} // DoMultiply()

template<bool A, bool S>
static void Multiply_ARM(CPU &instance) {
  uint8_t RsNumber = BitFieldValue<8, 4>(CURRENT_INSTRUCTION);
  uint8_t RdNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION);
  uint8_t RmNumber = BitFieldValue<0, 4>(CURRENT_INSTRUCTION);

  unsigned RsValue = instance._regs[RsNumber];
  unsigned RmValue = instance._regs[RmNumber];

  uint32_t result = DoMultiply<S>(instance, RmValue, RsValue);

  if constexpr (A) {
	instance.Idle();
	uint8_t RnNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION);
	unsigned RnValue = instance._regs[RnNumber];
	result += RnValue;
  } // if constexpr

  if constexpr (S) {
	// Result of C is meaningless, V is unaffected.
	result == 0 ? instance.SetZ() : instance.ClearZ();
	TestBit(result, 31) ? instance.SetN() : instance.ClearN();
  } // if constexpr

  instance._regs[RdNumber] = result;
} // Multiply()

template<bool U, bool A, bool S>
static void MultiplyLong_impl(CPU &instance) {
  uint32_t RsVal = instance._regs[BitFieldValue<8, 4>(CURRENT_INSTRUCTION)];
  uint32_t RmVal = instance._regs[BitFieldValue<0, 4>(CURRENT_INSTRUCTION)];

  uint8_t RdLoNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION);
  uint8_t RdHiNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION);

  union Mull_t {
	uint64_t qword;
	uint32_t dword[2];
	Mull_t(uint64_t val) { qword = val; }
  };

  Mull_t result = 0;
  unsigned m;
  if constexpr (!U) {
	m = UnsignedBoothCheck(RsVal);
	result = static_cast<uint64_t>(RsVal) * RmVal;
  } // if
  else {
	m = SignedBoothCheck(RsVal);
	const int64_t signedRs = (static_cast<int64_t>(RsVal) << 32) >> 32;
	const int64_t signedRm = (static_cast<int64_t>(RmVal) << 32) >> 32;
	result = signedRm * signedRs;
  } // else

  instance.Idle(m + 1);

  if constexpr (A) {
	uint64_t RdValue = (static_cast<uint64_t>(CPU_REG[RdHiNumber]) << 32) | CPU_REG[RdLoNumber];
	result.qword += RdValue;
	instance.Idle();
//	instance._elapsedClk += 1;
	// EMU_CLK += CLK_CONT.I_Cycle() ;
  } // if constexpr

  if constexpr (S) {
	TestBit(result.qword, 63) ? instance.SetN() : instance.ClearN();
	result.qword == 0 ? instance.SetZ() : instance.ClearZ();
  } // if constexpr

  CPU_REG[RdLoNumber] = result.dword[0];
  CPU_REG[RdHiNumber] = result.dword[1];

//  instance._mem.CalculateCycle(instance._regs[pc] + 4, sizeof(uint32_t), gg_mem::S_Cycle);
}
}

#endif //ARM_ANALYZER_V4_MULTIPLY_API_H

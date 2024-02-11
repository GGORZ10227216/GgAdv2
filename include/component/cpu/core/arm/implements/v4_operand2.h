//
// Created by buildmachine on 2020-11-27.
//

#include <cstdint>
#include <cpu_enum.h>

#ifndef GGTEST_V4_OPERAND2_H
#define GGTEST_V4_OPERAND2_H

namespace gg_core::gg_cpu {
template<E_ShiftType ST>
inline void Op2ShiftReg(CPU &instance, unsigned shiftBase, unsigned shiftAmount, uint32_t &result, bool &carryResult) {
  bool validShift = false;

  if constexpr (ST == E_ShiftType::LSL) {
	// todo: Does the behavior of shift_by_Rs_eq_zero and shift_by_imm_eq_zero same?
	if (shiftAmount == 0) {
	  carryResult = instance.C();
	  result = shiftBase;
	} // if
	else if (shiftAmount < 32) {
	  result = shiftBase << shiftAmount;
	  carryResult = TestBit(shiftBase, 33 - (shiftAmount + 1));
	  validShift = true;
	} // else if
	else {
	  result = 0;
	  carryResult = shiftAmount == 32 && TestBit(shiftBase, 0);
	  validShift = true;
	} // else
  } // if

  if constexpr (ST == E_ShiftType::LSR) {
	if (shiftAmount == 0) {
	  result = shiftBase;
	  carryResult = instance.C();
	} // if
	else if (shiftAmount < 32) {
	  result = shiftBase >> shiftAmount;
	  carryResult = TestBit(shiftBase, shiftAmount - 1);
	  validShift = true;
	} // else if
	else {
	  result = 0;
	  carryResult = shiftAmount == 32 && TestBit(shiftBase, shiftAmount - 1);
	  validShift = true;
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ASR) {
	if (shiftAmount >= 32) {
	  validShift = true;
	  carryResult = TestBit(shiftBase, 31);
	  result = carryResult ? 0xffffffff : 0x0;
	} // if
	else {
	  result = static_cast<int32_t>(shiftBase) >> shiftAmount;
	  if (shiftAmount != 0) {
		carryResult = TestBit(shiftBase, shiftAmount - 1);
		validShift = true;
	  } // if
	  else
		carryResult = instance.C();
	} // else if
  } // if

  if constexpr (ST == E_ShiftType::ROR) {
	result = rotr(shiftBase, shiftAmount);
	if (shiftAmount == 0)
	  carryResult = instance.C();
	else {
	  validShift = true;
	  carryResult = TestBit(result, 31);
	} // else
  } // if
} // Op2Shift()

template<E_ShiftType ST>
inline void Op2ShiftImm(CPU &instance, unsigned shiftBase, unsigned shiftAmount, uint32_t &result, bool &carryResult) {
  if constexpr (ST == E_ShiftType::LSL) {
	result = shiftBase << shiftAmount;
	if (shiftAmount != 0)
	  carryResult = TestBit(shiftBase, 33 - (shiftAmount + 1));
	else
	  carryResult = instance.C();
  } // if

  if constexpr (ST == E_ShiftType::LSR) {
	if (shiftAmount == 0) {
	  result = 0;
	  carryResult = TestBit(shiftBase, 31);
	} // if
	else {
	  result = shiftBase >> shiftAmount;
	  carryResult = TestBit(shiftBase, shiftAmount - 1);
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ASR) {
	if (shiftAmount == 0) {
	  carryResult = TestBit(shiftBase, 31);
	  result = carryResult ? 0xffffffff : 0x0;
	} // if
	else {
	  result = static_cast<int32_t>(shiftBase) >> shiftAmount;
	  carryResult = TestBit(shiftBase, shiftAmount - 1);
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ROR) {
	if (shiftAmount == 0) {
	  // RRX
	  carryResult = TestBit(shiftBase, 0);
	  result = (instance.C() << 31) | (shiftBase >> 1);
	} // if
	else {
	  result = rotr(shiftBase, shiftAmount);
	  carryResult = TestBit(result, 31);
	} // else
  } // if
} // Op2ShiftImm()

template<E_ShiftType ST>
inline bool ParseOp2_Shift_RS(CPU &instance, const unsigned RmNumber, const unsigned shiftAmount, uint32_t &op2) {
  uint32_t &Rm = instance._regs[RmNumber];

  // Rm == PC + 12 is shift by reg only
  // According to the ARM7TDMI manual, 4.5.2 Shifts, seems Rs can't be PC(r15)
  if (RmNumber == pc)
	Rm = (Rm + instance.instructionLength);

  return Op2ShiftReg<ST>(instance, op2, Rm, shiftAmount);
} // ParseOp2_Shift_RS()

template<E_ShiftType ST>
inline bool ParseOp2_Shift_Imm(CPU &instance, const unsigned RmNumber, const unsigned shiftAmount, uint32_t &op2) {
  uint32_t Rm = instance._regs[RmNumber];
//  const uint8_t shiftAmount = (curInst & 0xf80) >> 7;

  return Op2ShiftImm<ST>(instance, op2, Rm, shiftAmount);
} // ParseOp2_Shift_Imm()

inline bool ParseOp2_Imm(CPU &instance, const unsigned imm, const unsigned rot, uint32_t &op2) {
  op2 = rotr(imm, rot);
  if (rot == 0)
	return instance.C();
  else
	return TestBit(op2, 31);
} // ParseOp2_Imm()
}

#endif //GGTEST_V4_OPERAND2_H

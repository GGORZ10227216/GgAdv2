//
// Created by buildmachine on 2020-11-27.
//

#include <cstdint>
#include <cpu_enum.h>

#ifndef GGTEST_V4_OPERAND2_H
#define GGTEST_V4_OPERAND2_H

namespace gg_core::gg_cpu {
template<E_ShiftType ST>
inline bool Op2ShiftReg(CPU &instance, uint32_t &result, unsigned shiftBase, unsigned shiftAmount) {
  bool validShift = false, carrySet = false;

  if constexpr (ST == E_ShiftType::LSL) {
	// todo: Does the behavior of shift_by_Rs_eq_zero and shift_by_imm_eq_zero same?
	if (shiftAmount == 0) {
	  carrySet = instance.C();
	  result = shiftBase;
	} // if
	else if (shiftAmount < 32) {
	  result = shiftBase << shiftAmount;
	  carrySet = TestBit(shiftBase, 33 - (shiftAmount + 1));
	  validShift = true;
	} // else if
	else {
	  result = 0;
	  carrySet = shiftAmount == 32 && TestBit(shiftBase, 0);
	  validShift = true;
	} // else
  } // if

  if constexpr (ST == E_ShiftType::LSR) {
	if (shiftAmount == 0) {
	  result = shiftBase;
	  carrySet = instance.C();
	} // if
	else if (shiftAmount < 32) {
	  result = shiftBase >> shiftAmount;
	  carrySet = TestBit(shiftBase, shiftAmount - 1);
	  validShift = true;
	} // else if
	else {
	  result = 0;
	  carrySet = shiftAmount == 32 && TestBit(shiftBase, shiftAmount - 1);
	  validShift = true;
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ASR) {
	if (shiftAmount >= 32) {
	  validShift = true;
	  carrySet = TestBit(shiftBase, 31);
	  result = carrySet ? 0xffffffff : 0x0;
	} // if
	else {
	  result = static_cast<int32_t>(shiftBase) >> shiftAmount;
	  if (shiftAmount != 0) {
		carrySet = TestBit(shiftBase, shiftAmount - 1);
		validShift = true;
	  } // if
	  else
		carrySet = instance.C();
	} // else if
  } // if

  if constexpr (ST == E_ShiftType::ROR) {
	result = rotr(shiftBase, shiftAmount);
	if (shiftAmount == 0)
	  carrySet = instance.C();
	else {
	  validShift = true;
	  carrySet = TestBit(result, 31);
	} // else
  } // if

  if (validShift) {
	instance.AddCycle(1, "Shift by reg");
//	instance._elapsedClk += 1; // Shift by reg will add 1 I_Cycle cycle
  } // if

  return carrySet;
} // Op2Shift()

template<E_ShiftType ST>
inline bool Op2ShiftImm(CPU &instance, uint32_t &result, unsigned shiftBase, unsigned shiftAmount) {
  bool carry = false;
  if constexpr (ST == E_ShiftType::LSL) {
	result = shiftBase << shiftAmount;
	if (shiftAmount != 0)
	  carry = TestBit(shiftBase, 33 - (shiftAmount + 1));
	else
	  carry = instance.C();
  } // if

  if constexpr (ST == E_ShiftType::LSR) {
	if (shiftAmount == 0) {
	  result = 0;
	  carry = TestBit(shiftBase, 31);
	} // if
	else {
	  result = shiftBase >> shiftAmount;
	  carry = TestBit(shiftBase, shiftAmount - 1);
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ASR) {
	if (shiftAmount == 0) {
	  carry = TestBit(shiftBase, 31);
	  result = carry ? 0xffffffff : 0x0;
	} // if
	else {
	  result = static_cast<int32_t>(shiftBase) >> shiftAmount;
	  carry = TestBit(shiftBase, shiftAmount - 1);
	} // else
  } // if

  if constexpr (ST == E_ShiftType::ROR) {
	if (shiftAmount == 0) {
	  // RRX
	  carry = TestBit(shiftBase, 0);
	  result = (instance.C() << 31) | (shiftBase >> 1);
	} // if
	else {
	  result = rotr(shiftBase, shiftAmount);
	  carry = TestBit(result, 31);
	} // else
  } // if

  return carry;
}

template<E_ShiftType ST>
inline bool ParseOp2_Shift_RS(CPU &instance, uint32_t &op2) {
  const uint32_t curInst = CURRENT_INSTRUCTION;
  const uint8_t RmNumber = curInst & 0b1111;
  const uint8_t RsNumber = (curInst & 0xf00) >> 8;

  uint32_t Rm = instance._regs[RmNumber];
  uint32_t Rs = instance._regs[RsNumber] & 0xff;

  // Rm == PC + 12 is shift by reg only
  if (RmNumber == pc)
	Rm = (Rm + 4);

  return Op2ShiftReg<ST>(instance, op2, Rm, Rs);
} // ParseOp2_Shift_RS()

template<E_ShiftType ST>
inline bool ParseOp2_Shift_Imm(CPU &instance, uint32_t &op2) {
  const uint32_t curInst = CURRENT_INSTRUCTION;
  uint32_t Rm = instance._regs[curInst & 0b1111];
  const uint8_t shiftAmount = (curInst & 0xf80) >> 7;

  return Op2ShiftImm<ST>(instance, op2, Rm, shiftAmount);
} // ParseOp2_Shift_Imm()

inline bool ParseOp2_Imm(CPU &instance, uint32_t &op2) {
  const uint32_t curInst = CURRENT_INSTRUCTION;
  const uint32_t imm = curInst & 0xff;
  const uint8_t rot = (curInst & 0xf00) >> 7;
  op2 = rotr(imm, rot);
  if (rot == 0)
	return instance.C();
  else
	return TestBit(op2, 31);
} // ParseOp2_Imm()
}

#endif //GGTEST_V4_OPERAND2_H

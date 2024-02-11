//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT4_H
#define GGTEST_V4T_FORMAT4_H

namespace gg_core::gg_cpu {
template<E_DataProcess OP, SHIFT_BY SHIFT_SRC, E_ShiftType ST>
extern void ALU_Operations(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned RsNumber = (curInst & 0b111000) >> 3;
  const unsigned RdNumber = curInst & 0b111;

//  ALU_Fetch<SHIFT_SRC>(instance, RdNumber);

  const unsigned op1 = instance._regs[RdNumber];
  unsigned op2;
  bool carryResult;

  if constexpr (SHIFT_SRC != SHIFT_BY::NONE) {
	const unsigned shiftAmount = instance._regs[RsNumber];
	ALU_CalculateShiftOp2<SHIFT_SRC, ST>(instance, RdNumber, shiftAmount, op2, carryResult);
  } // if constexpr
  else {
	op2 = instance._regs[RsNumber];
	carryResult = instance.C();
  } // else

  if constexpr (OP == RSB) {
	// NEG <--> RSBS Rd, Rs, #0
	ALU_Execute<uint32_t, true, OP>(
		instance,
		RdNumber,
		op2,
		0,
		carryResult
	);
  } // if constexpr
  else {
	ALU_Execute<uint32_t, true, OP>(
		instance,
		RdNumber,
		op1,
		op2,
		carryResult
	);
  } // else
} // MovCmpAddSub()

static void Multiply_Thumb(CPU &instance) {
  const unsigned RsNumber = (CURRENT_INSTRUCTION & 0b111000) >> 3;
  const unsigned RdNumber = CURRENT_INSTRUCTION & 0b111;

  uint32_t result;
  const uint32_t RsValue = instance._regs[RsNumber];
  const uint32_t RdValue = instance._regs[RdNumber];

  result = DoMultiply<true>(instance, RsValue, RdValue);
  instance._regs[RdNumber] = result;

  // Thumb Multiply always set the CPSR
  result == 0 ? instance.SetZ() : instance.ClearZ();
  TestBit(result, 31) ? instance.SetN() : instance.ClearN();
} // Multiply_Thumb()
}

#endif //GGTEST_V4T_FORMAT4_H

//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT1_H
#define GGTEST_V4T_FORMAT1_H

namespace gg_core::gg_cpu {
using namespace gg_core::gg_mem;

template<E_ShiftType ST>
extern void MoveShift(CPU &instance) {
  if constexpr (ST == ROR)
	gg_core::Unreachable();

  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned RsNumber = (curInst & 0b111000) >> 3;
  const unsigned RdNumber = (curInst & 0b111);

  const unsigned shiftAmount = (curInst & (0b11111 << 6)) >> 6;
  bool carryResult = false;
  uint32_t op2 = 0;
  uint32_t result = 0;

//  ALU_Fetch<SHIFT_BY::IMM>(instance, RdNumber);
  ALU_CalculateShiftOp2<SHIFT_BY::IMM, ST>(instance, RsNumber, shiftAmount, op2, carryResult);

  // We don't care about Op1, so just pass 0.
  ALU_Execute<uint32_t, true, E_DataProcess::MOV>(instance, RdNumber, 0, op2, carryResult);
} // MoveShift()
}

#endif //GGTEST_V4T_FORMAT1_H

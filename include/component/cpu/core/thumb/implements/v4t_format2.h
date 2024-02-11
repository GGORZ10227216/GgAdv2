//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT2_H
#define GGTEST_V4T_FORMAT2_H

namespace gg_core::gg_cpu {
using namespace gg_core::gg_mem;

template<bool IS_IMMEDIATE, E_DataProcess OPCODE>
extern void AddSub(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned RsNumber = (curInst & 0b111000) >> 3;
  const unsigned RdNumber = (curInst & 0b111);
  const unsigned imm = (curInst & (0b111 << 6)) >> 6;

  bool carryResult = instance.C();
  uint32_t op2 = 0;

  if constexpr (IS_IMMEDIATE) {
	op2 = imm;
  } // if constexpr
  else {
	op2 = instance._regs[imm];
  } // else

  ALU_Execute<uint32_t, true, OPCODE>(instance, RdNumber, instance._regs[RsNumber], op2, carryResult);
}
}

#endif //GGTEST_V4T_FORMAT2_H

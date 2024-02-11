//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT3_H
#define GGTEST_V4T_FORMAT3_H

namespace gg_core::gg_cpu {
using namespace gg_core::gg_mem;

template<E_DataProcess OP>
extern void MovCmpAddSub(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned offset8 = curInst & 0xff;
  const unsigned RdNumber = (curInst & 0x700) >> 8;
  const unsigned op1 = instance._regs[RdNumber];

//  ALU_Fetch<SHIFT_BY::NONE>(instance, RdNumber);
  ALU_Execute<uint32_t, true, OP>(instance, RdNumber, op1, offset8, instance.C());
} // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT3_H

//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT13_H
#define GGTEST_V4T_FORMAT13_H

namespace gg_core::gg_cpu {
template<bool S>
extern void SP_Offset(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const int offsetImm = (curInst & 0x7f) << 2; // 9 bit offset

  if constexpr (S)
	instance._regs[sp] -= offsetImm;
  else
	instance._regs[sp] += offsetImm;
} // SP_Offset()
}

#endif //GGTEST_V4T_FORMAT13_H

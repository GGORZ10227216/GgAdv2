//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT12_H
#define GGTEST_V4T_FORMAT12_H

namespace gg_core::gg_cpu {
template<bool SP>
extern void LoadAddress(CPU &instance) {
  instance.Fetch(&instance, S_Cycle);

  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned targetRd = (curInst & (0b111 << 8)) >> 8;
  const unsigned offsetImm = (curInst & 0xff) << 2; // 10 bit offset

  if constexpr (SP)
	instance._regs[targetRd] = instance._regs[sp] + offsetImm;
  else
	instance._regs[targetRd] = instance._regs[pc] + offsetImm;
} // SP_RelativeLoadStore()
}

#endif //GGTEST_V4T_FORMAT12_H

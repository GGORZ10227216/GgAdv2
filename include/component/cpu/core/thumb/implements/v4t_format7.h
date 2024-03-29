//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT7_H
#define GGTEST_V4T_FORMAT7_H

namespace gg_core::gg_cpu {
template<bool L, bool B>
extern void LoadStoreRegOffset(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned targetRd = curInst & 0b111;
  const unsigned baseReg = (curInst & (0b111 << 3)) >> 3;
  const unsigned offsetReg = (curInst & (0b111 << 6)) >> 6;

  const unsigned targetAddr = instance._regs[baseReg] + instance._regs[offsetReg];

  if constexpr (L) {
	if constexpr (B)
	  MemLoad<uint8_t, false>(instance, targetAddr, targetRd);
	else
	  MemLoad<uint32_t, false>(instance, targetAddr, targetRd);
  } // if
  else {
	if constexpr (B)
	  MemStore<uint8_t>(instance, targetAddr, targetRd);
	else
	  MemStore<uint32_t>(instance, targetAddr, targetRd);
  } // else
} // LoadStoreRegOffset()
}

#endif //GGTEST_V4T_FORMAT7_H

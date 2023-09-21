//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT8_H
#define GGTEST_V4T_FORMAT8_H

namespace gg_core::gg_cpu {
template<bool H, bool S>
extern void LoadStoreRegOffsetSignEx(CPU &instance) {
  instance.Fetch(&instance, N_Cycle);

  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned targetRd = curInst & 0b111;
  const unsigned baseReg = (curInst & (0b111 << 3)) >> 3;
  const unsigned offsetReg = (curInst & (0b111 << 6)) >> 6;

  const unsigned targetAddr = instance._regs[baseReg] + instance._regs[offsetReg];

  if constexpr (S) {
	if constexpr (H)
	  MemLoad<uint16_t, true>(instance, targetAddr, targetRd);
	else
	  MemLoad<uint8_t, true>(instance, targetAddr, targetRd);
  } // if
  else {
	if constexpr (H)
	  MemLoad<uint16_t, false>(instance, targetAddr, targetRd);
	else
	  MemStore<uint16_t>(instance, targetAddr, targetRd);
  } // else
} // LoadStoreRegOffsetSignEx()
}

#endif //GGTEST_V4T_FORMAT8_H

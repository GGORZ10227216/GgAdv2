//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT14_H
#define GGTEST_V4T_FORMAT14_H

namespace gg_core::gg_cpu {
template<bool L, bool R>
extern void PushPop(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  unsigned regList = curInst & 0xff;

  if constexpr (L) {
	if constexpr (R)
	  regList |= (1 << pc);
	PushPop<true, false, true, true>(instance, sp, regList, PopCount32(regList) << 2);
  } // if
  else {
	if constexpr (R)
	  regList |= (1 << lr);
	PushPop<false, true, false, true>(instance, sp, regList, PopCount32(regList) << 2);
  } // else
} // SP_Offset()
}

#endif //GGTEST_V4T_FORMAT14_H

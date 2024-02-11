//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT15_H
#define GGTEST_V4T_FORMAT15_H

namespace gg_core::gg_cpu {
template<bool L>
extern void MultiLoadStore(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  unsigned baseRegNum = (curInst & (0b111 << 8)) >> 8;
  unsigned regList = curInst & 0xff;
  unsigned offset = PopCount32(regList) << 2;

  if (regList == 0) {
	regList = 0x8000;
	offset = 0x40;
  } // if

  PushPop<L, false, true, true>(instance, baseRegNum, regList, offset);
} // SP_Offset()
}

#endif //GGTEST_V4T_FORMAT15_H

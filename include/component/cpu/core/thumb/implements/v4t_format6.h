//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT6_H
#define GGTEST_V4T_FORMAT6_H

namespace gg_core::gg_cpu {
extern void PC_RelativeLoad(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned targetRd = (curInst & (0b111 << 8)) >> 8;
  const unsigned immOffset = (curInst & 0xff) << 2; // 10bit offset

  const uint32_t pcValue = instance._regs[pc] & ~0b11; // force pc's to word aligned

  MemLoad<uint32_t, false>(instance, pcValue + immOffset, targetRd);
} // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT6_H

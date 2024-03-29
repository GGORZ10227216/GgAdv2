//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT16_H
#define GGTEST_V4T_FORMAT16_H

namespace gg_core::gg_cpu {
extern void ConditionalBranch(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  unsigned condition = (curInst & (0xf << 8)) >> 8;

  auto checker = instance.conditionChecker[condition];

  if ((instance.*checker)()) {
	int32_t sOffset = (static_cast<int32_t>(curInst & 0xff) << 24) >> 23;

	instance._regs[pc] += sOffset;
	instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);
  } // if
} // ConditionalBranch()
}

#endif //GGTEST_V4T_FORMAT16_H

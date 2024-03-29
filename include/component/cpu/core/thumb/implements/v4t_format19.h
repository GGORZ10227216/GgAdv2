//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT19_H
#define GGTEST_V4T_FORMAT19_H

namespace gg_core::gg_cpu {
template<bool H>
extern void LongBranch(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  unsigned offset = static_cast<int16_t>(curInst & 0x7ff);

  if constexpr (!H) {
	instance._regs[lr] = instance._regs[pc] + ((static_cast<int32_t>(offset) << 21) >> 9);
  } // if
  else {
	uint32_t blNextPC = instance._regs[pc] - 2;

	instance._regs[pc] = instance._regs[lr] + (offset << 1);
	instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);

	instance._regs[lr] = blNextPC | 0x1;
  } // else
} // LongBranch()
}

#endif //GGTEST_V4T_FORMAT19_H

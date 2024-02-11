//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT12_H
#define GGTEST_V4T_FORMAT12_H

namespace gg_core::gg_cpu {
template<bool SP>
extern void LoadAddress(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  const unsigned targetRd = (curInst & (0b111 << 8)) >> 8;
  const unsigned offsetImm = (curInst & 0xff) << 2; // 10 bit offset

  if constexpr (SP)
	instance._regs[targetRd] = instance._regs[sp] + offsetImm;
  else {
	// ARM7TDMI manual 5.12.1, the Note says:
	//     Where the PC is used as the source register (SP = 0), bit 1 of the PC is always read
	//     as 0.
	instance._regs[targetRd] = (instance._regs[pc] & ~0b10) + offsetImm;
  } // else
} // SP_RelativeLoadStore()
}

#endif //GGTEST_V4T_FORMAT12_H

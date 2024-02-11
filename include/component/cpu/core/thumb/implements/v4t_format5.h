//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT5_H
#define GGTEST_V4T_FORMAT5_H

namespace gg_core::gg_cpu {
template<auto OP, bool H1, bool H2>
extern void HiRegOperation_BX(CPU &instance) {
  const uint16_t curInst = CURRENT_INSTRUCTION;
  unsigned RsNumber = (curInst & 0b111000) >> 3;
  unsigned RdNumber = curInst & 0b111;

  if constexpr (H1) {
	RdNumber += 8;
  }
  if constexpr (H2) {
	RsNumber += 8;
  }

  if constexpr (std::is_same_v<decltype(OP), E_DataProcess>) {
//	ALU_Fetch<SHIFT_BY::NONE>(instance, RdNumber);

	const uint32_t RsValue = instance._regs[RsNumber];
	const uint32_t RdValue = instance._regs[RdNumber];
	const bool S = OP == CMP;

	ALU_Execute<uint32_t, S, OP>(instance, RdNumber, RdValue, RsValue, instance.C());
  } // if
  else {
	BX(instance, RsNumber);
  } // else
} // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT5_H

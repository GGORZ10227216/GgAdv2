//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE2_H
#define GGTEST_TYPE2_H

namespace gg_core::gg_cpu {
template<bool IS_IMMEDIATE, E_DataProcess OPCODE>
extern void AddSub(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType2() {
  constexpr bool IS_IMMEDIATE = TestBit(HashCode10, 4);
  constexpr E_DataProcess OPCODE = []() {
	if constexpr (TestBit(HashCode10, 3))
	  return E_DataProcess::SUB;
	else
	  return E_DataProcess::ADD;
  }();

  return &AddSub<IS_IMMEDIATE, OPCODE>;
} // ThumbType2()
}

#endif //GGTEST_TYPE2_H

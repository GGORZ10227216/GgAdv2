//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE9_H
#define GGTEST_TYPE9_H

namespace gg_core::gg_cpu {
template<bool L, bool B>
extern void LoadStoreImmOffset(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType9() {
  constexpr bool L = TestBit(HashCode10, 5);
  constexpr bool B = TestBit(HashCode10, 6);

  return &LoadStoreImmOffset<L, B>;
}
}

#endif //GGTEST_TYPE9_H

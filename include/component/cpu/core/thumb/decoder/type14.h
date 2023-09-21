//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE14_H
#define GGTEST_TYPE14_H

namespace gg_core::gg_cpu {
template<bool L, bool R>
extern void PushPop(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType14() {
  constexpr bool L = TestBit(HashCode10, 5);
  constexpr bool R = TestBit(HashCode10, 2);

  return &PushPop<L, R>;
}
}

#endif //GGTEST_TYPE14_H

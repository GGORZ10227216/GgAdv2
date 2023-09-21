//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE15_H
#define GGTEST_TYPE15_H

namespace gg_core::gg_cpu {
template<bool L>
extern void MultiLoadStore(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType15() {
  constexpr bool L = TestBit(HashCode10, 5);

  return &MultiLoadStore<L>;
}
}

#endif //GGTEST_TYPE15_H

//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE11_H
#define GGTEST_TYPE11_H

namespace gg_core::gg_cpu {
template<bool L>
extern void SP_RelativeLoadStore(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType11() {
  constexpr bool L = TestBit(HashCode10, 5);

  return &SP_RelativeLoadStore<L>;
}
}

#endif //GGTEST_TYPE11_H

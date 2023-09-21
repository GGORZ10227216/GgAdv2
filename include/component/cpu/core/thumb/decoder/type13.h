//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE13_H
#define GGTEST_TYPE13_H

namespace gg_core::gg_cpu {
template<bool S>
extern void SP_Offset(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType13() {
  constexpr bool S = TestBit(HashCode10, 1);
  return &SP_Offset<S>;
}
}

#endif //GGTEST_TYPE13_H

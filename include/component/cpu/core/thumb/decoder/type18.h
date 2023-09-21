//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE18_H
#define GGTEST_TYPE18_H

namespace gg_core::gg_cpu {
extern void UnconditionalBranch(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType18() {
  return &UnconditionalBranch;
}
}

#endif //GGTEST_TYPE18_H

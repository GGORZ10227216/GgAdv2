//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE6_H
#define GGTEST_TYPE6_H

namespace gg_core::gg_cpu {
extern void PC_RelativeLoad(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType6() {
  return &PC_RelativeLoad;
}
}

#endif //GGTEST_TYPE6_H

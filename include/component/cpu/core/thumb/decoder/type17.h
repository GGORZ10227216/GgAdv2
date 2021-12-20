//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE17_H
#define GGTEST_TYPE17_H

namespace gg_core::gg_cpu {
    extern void SoftInterrupt(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType17() {
        return &SoftInterrupt;
    }
}

#endif //GGTEST_TYPE17_H

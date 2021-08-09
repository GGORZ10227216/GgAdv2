//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE19_H
#define GGTEST_TYPE19_H

namespace gg_core::gg_cpu {
    template <bool H>
    static void LongBranch(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType19() {
        constexpr bool H = TestBit(HashCode10, 5) ;
        return &LongBranch<H>;
    }
}

#endif //GGTEST_TYPE19_H

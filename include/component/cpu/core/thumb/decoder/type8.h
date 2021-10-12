//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE8_H
#define GGTEST_TYPE8_H

namespace gg_core::gg_cpu {
    template <bool H, bool S>
    static void LoadStoreRegOffsetSignEx(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType8() {
        constexpr bool H = TestBit(HashCode10, 5) ;
        constexpr bool S = TestBit(HashCode10, 4) ;

        return &LoadStoreRegOffsetSignEx<H, S>;
    }
}

#endif //GGTEST_TYPE8_H

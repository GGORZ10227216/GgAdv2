//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE10_H
#define GGTEST_TYPE10_H

namespace gg_core::gg_cpu {
    template <bool L>
    static void LoadStoreImmOffsetHalf(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType10() {
        constexpr bool L = TestBit(HashCode10, 5) ;

        return &LoadStoreImmOffsetHalf<L>;
    }
}

#endif //GGTEST_TYPE10_H

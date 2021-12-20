//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE7_H
#define GGTEST_TYPE7_H

namespace gg_core::gg_cpu {
    template <bool L, bool B>
    extern void LoadStoreRegOffset(CPU& instance);

    template <uint32_t HashCode10>
    static constexpr auto ThumbType7() {
        constexpr bool L = TestBit(HashCode10, 5) ;
        constexpr bool B = TestBit(HashCode10, 4) ;

        return &LoadStoreRegOffset<L, B>;
    }
}

#endif //GGTEST_TYPE7_H

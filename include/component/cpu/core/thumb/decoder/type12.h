//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE12_H
#define GGTEST_TYPE12_H

namespace gg_core::gg_cpu {
    template <bool SP>
    static void LoadAddress(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType12() {
        constexpr bool SP = TestBit(HashCode10, 5) ;
        return &LoadAddress<SP>;
    }
}

#endif //GGTEST_TYPE12_H

//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE16_H
#define GGTEST_TYPE16_H

namespace gg_core::gg_cpu {
    static void ConditionalBranch(CPU& instance)  ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType16() {
        return &ConditionalBranch;
    }
}

#endif //GGTEST_TYPE16_H

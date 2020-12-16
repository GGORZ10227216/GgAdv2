//
// Created by buildmachine on 2020-11-30.
//

#ifndef GGTEST_BRANCH_H
#define GGTEST_BRANCH_H

namespace gg_core::gg_cpu {
    static void BranchExchange_impl(GbaInstance& instance);

    template <bool L>
    static void Branch_impl(GbaInstance& instance);

    template <uint32_t HashCode32>
    static constexpr auto Branch() {
        return &Branch_impl<
            TestBit(HashCode32, 24)
        > ;
    }

    static constexpr auto BranchExchange() {
        // BX has no flag on it, so no need to analyze hashcode
        return &BranchExchange_impl;
    }
}

#endif //GGTEST_BRANCH_H

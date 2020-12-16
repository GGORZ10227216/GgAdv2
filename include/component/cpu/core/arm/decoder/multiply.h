//
// Created by buildmachine on 2020-11-30.
//

#include <cstdint>

#include <bit_manipulate.h>

#ifndef GGTEST_MULTIPLY_H
#define GGTEST_MULTIPLY_H

namespace gg_core::gg_cpu {
    template<bool A, bool S>
    static void Multiply_impl(GbaInstance &instance);

    template<bool U, bool A, bool S>
    static void MultiplyLong_impl(GbaInstance &instance);

    template<uint32_t HashCode32>
    static constexpr auto Multiply() {
        constexpr bool A = TestBit(HashCode32, 21);
        constexpr bool S = TestBit(HashCode32, 20);
        return &Multiply_impl<A, S>;
    }

    template <uint32_t HashCode32>
    static constexpr auto MultiplyLong() {
        constexpr bool U = TestBit(HashCode32, 22);
        constexpr bool A = TestBit(HashCode32, 21);
        constexpr bool S = TestBit(HashCode32, 20);
        return &MultiplyLong_impl<U, A, S>;
    }
}

#endif //GGTEST_MULTIPLY_H

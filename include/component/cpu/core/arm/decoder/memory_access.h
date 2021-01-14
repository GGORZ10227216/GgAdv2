//
// Created by buildmachine on 2020-11-30.
//

#include <cstdint>

#include <cpu_enum.h>
#include <bit_manipulate.h>

#ifndef GGTEST_MEMORY_ACCESS_H
#define GGTEST_MEMORY_ACCESS_H

namespace gg_core::gg_cpu {
    template<bool I, bool P, bool U, bool B, bool W, bool L, SHIFT_TYPE ST>
    static void SingleDataTransfer_impl(GbaInstance &instance);

    template<bool P, bool U, bool W, bool L, bool S, bool H, OFFSET_TYPE OT>
    static void HalfMemAccess_impl(GbaInstance &instance);

    template<bool P, bool U, bool S, bool W, bool L>
    static void BlockMemAccess_impl(GbaInstance &instance);

    template<bool B>
    static void Swap_impl(GbaInstance &instance);

    template<uint32_t HashCode32>
    static constexpr auto SingleDataTransfer() {
        constexpr enum SHIFT_TYPE ST =
                static_cast<SHIFT_TYPE>(BitFieldValue<5, 2>(HashCode32));
        return &SingleDataTransfer_impl<
                TestBit(HashCode32, 25),
                TestBit(HashCode32, 24),
                TestBit(HashCode32, 23),
                TestBit(HashCode32, 22),
                TestBit(HashCode32, 21),
                TestBit(HashCode32, 20),
                ST
        >;
    } // SingleDataTransfer()

    template<uint32_t HashCode32>
    static constexpr auto HalfDataTransfer() {
        constexpr enum OFFSET_TYPE OT = TestBit(HashCode32, 22) ?
                                        OFFSET_TYPE::IMM : OFFSET_TYPE::RM;
        return &HalfMemAccess_impl<
                TestBit(HashCode32, 24),
                TestBit(HashCode32, 23),
                TestBit(HashCode32, 21),
                TestBit(HashCode32, 20),
                TestBit(HashCode32, 6),
                TestBit(HashCode32, 5),
                OT
        >;
    } // HalfDataTransfer()

    template<uint32_t HashCode32>
    static constexpr auto BlockDataTransfer() {
        return &BlockMemAccess_impl<
                TestBit(HashCode32, 24),
                TestBit(HashCode32, 23),
                TestBit(HashCode32, 22),
                TestBit(HashCode32, 21),
                TestBit(HashCode32, 20)
        >;
    }

    template<uint32_t HashCode32>
    static constexpr auto Swap() {
        return &Swap_impl<
                TestBit(HashCode32, 22)
        >;
    } // Swap()
}

#endif //GGTEST_MEMORY_ACCESS_H

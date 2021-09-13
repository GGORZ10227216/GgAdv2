//
// Created by buildmachine on 2020-11-30.
//

#include <cstdint>

#include <cpu_enum.h>
#include <bit_manipulate.h>

#ifndef GGTEST_DATA_PROCESSING_H
#define GGTEST_DATA_PROCESSING_H

namespace gg_core::gg_cpu {
    class CPU ; // Forward declaration of cpu class

    template<bool I, bool S, SHIFT_BY SHIFT_SRC, E_ShiftType ST, E_DataProcess opcode>
    static void ALU_ARM_Operation(CPU &instance) ;

    template <uint32_t HashCode32>
    static constexpr auto DataProcessing() {
        constexpr auto opcode = static_cast<const E_DataProcess>(BitFieldValue<21, 4>(HashCode32));
        constexpr auto SHIFT_SRC = TestBit(HashCode32, 4) ? SHIFT_BY::RS : SHIFT_BY::IMM ;
        constexpr auto ST = static_cast<E_ShiftType>(BitFieldValue<5,2>(HashCode32)) ;
        return &ALU_ARM_Operation<
                TestBit(HashCode32, 25),
                TestBit(HashCode32, 20),
                SHIFT_SRC,
                ST,
                opcode
        >;
    }
}

#endif //GGTEST_DATA_PROCESSING_H

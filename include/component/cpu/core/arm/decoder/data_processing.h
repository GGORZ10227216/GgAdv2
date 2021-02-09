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

    template<bool I, bool S, bool TEST, SHIFT_BY SHIFT_SRC, SHIFT_TYPE ST, OP_TYPE OT, E_DataProcess opcode>
    static void Alu_impl(CPU &instance) ;

    template <uint32_t HashCode32>
    static constexpr auto DataProcessing() {
        constexpr auto opcode = static_cast<const E_DataProcess>(BitFieldValue<21, 4>(HashCode32));
        constexpr bool TEST = opcode == TST || opcode == TEQ || opcode == CMP || opcode == CMN ;
        constexpr auto SHIFT_SRC = TestBit(HashCode32, 4) ? SHIFT_BY::RS : SHIFT_BY::IMM ;
        constexpr auto ST = static_cast<SHIFT_TYPE>(BitFieldValue<5,2>(HashCode32)) ;
        constexpr enum OP_TYPE OT = (opcode >= SUB && opcode <= RSC) || (opcode == CMP || opcode == CMN) ?
                                    OP_TYPE::ARITHMETIC : OP_TYPE::LOGICAL ;
        return &Alu_impl<
                TestBit(HashCode32, 25),
                TestBit(HashCode32, 20),
                TEST,
                SHIFT_SRC,
                ST,
                OT,
                opcode
        >;
    }
}

#endif //GGTEST_DATA_PROCESSING_H

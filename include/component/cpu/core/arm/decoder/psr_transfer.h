//
// Created by buildmachine on 2020-11-30.
//

#include <bit_manipulate.h>
#include <gg_utility.h>

#ifndef GGTEST_INTERRUPT_H
#define GGTEST_INTERRUPT_H

namespace gg_core::gg_cpu {
    static void mrs(GbaInstance& instance) ;
    static void msr_Rm(GbaInstance& instance) ;
    static void mrsp(GbaInstance& instance) ;
    static void msrp_Rm(GbaInstance& instance) ;
    static void msr_Imm(GbaInstance& instance) ;
    static void msrp_Imm(GbaInstance& instance) ;

    template <uint32_t HashCode32>
    static constexpr auto PSR_Transfer() {
        if constexpr (BitFieldValue<20,2>(HashCode32) == 0b00) {
            // MRS
            if constexpr (TestBit(HashCode32, 22))
                return &mrsp;
            else
                return &mrs;
        } // if
        else if constexpr (BitFieldValue<20,2>(HashCode32) == 0b10) {
            // MSR
            if constexpr (TestBit(HashCode32, 25)) {
                if constexpr (TestBit(HashCode32, 22))
                    return &msrp_Imm;
                else
                    return &msr_Imm;
            } // if
            else {
                if constexpr (TestBit(HashCode32, 22))
                    return &msrp_Rm;
                else
                    return &msr_Rm;
            } // else
        } // else
        else
            Unreachable() ;
    } // PSR_Transfer()
}

#endif //GGTEST_INTERRUPT_H

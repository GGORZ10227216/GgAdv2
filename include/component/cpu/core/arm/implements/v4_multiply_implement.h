//
// Created by jason4_lee on 2020-10-06.
//

#include <bit_manipulate.h>

#ifndef ARM_ANALYZER_V4_MULTIPLY_API_H
#define ARM_ANALYZER_V4_MULTIPLY_API_H

namespace gg_core::gg_cpu {
    template<bool A, bool S>
    void Multiply_impl(GbaInstance &instance) {
        uint8_t RsNumber = BitFieldValue<8, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RdNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RmNumber = BitFieldValue<0, 4>(CURRENT_INSTRUCTION) ;

        unsigned RsValue = instance._status._regs[ RsNumber ] ;
        unsigned RmValue = instance._status._regs[ RmNumber ] ;

        unsigned boothValue = 4;
        for (int i = 1; i < 4; ++i) {
            unsigned boothCheck = RsValue >> (8 * i);
            const uint32_t allOneMask = 0xffffffff;
            if (boothCheck == 0 || boothCheck == allOneMask >> (8 * i)) {
                boothValue = i;
                break;
            } // if
        } // for

        uint32_t result = RmValue * RsValue ;

        if constexpr (A) {
            uint8_t RnNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION);
            unsigned RnValue = instance._status._regs[ RnNumber ] ;
            result += RnValue ;
        } // if

        instance._status._regs[RdNumber] = result ;

        if constexpr (S) {
            // Result of C is meaningless, V is unaffected.
            result == 0 ? instance._status.SetZ() : instance._status.ClearZ();
            TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN();
        } // if
    } // Multiply()

    template<bool U, bool A, bool S>
    void MultiplyLong_impl(GbaInstance &instance) {
        uint64_t RsVal = instance._status._regs[BitFieldValue<8, 4>(CURRENT_INSTRUCTION)] ;
        uint64_t RmVal = instance._status._regs[BitFieldValue<0, 4>(CURRENT_INSTRUCTION)] ;

        uint8_t RdLoNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RdHiNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ;

        union Mull_t {
            uint64_t qword ;
            uint32_t dword[2] ;
            Mull_t(uint64_t val) {qword = val;}
        };

        uint64_t RdValue = (static_cast<uint64_t>(CPU_REG[RdHiNumber]) << 32) | CPU_REG[RdLoNumber] ;
        Mull_t result = RdValue + RsVal*RmVal ;

        unsigned boothValue = 4;
        for (int i = 1; i < 4; ++i) {
            unsigned boothCheck = RsVal >> (8 * i);
            if constexpr (U) {
                const unsigned allOneMask = 0xffffffff;
                if (boothCheck == 0 || boothCheck == allOneMask >> (8 * i)) {
                    boothValue = i;
                    break;
                } // if
            } // if constexpr
            else {
                if (boothCheck == 0) {
                    boothValue = i;
                    break;
                } // if
            } // else
        } // for

        // EMU_CLK += CLK_CONT.S(EMU_CPU.ProgramCounter()) + CLK_CONT.I() * (boothValue + 1);

        if constexpr (A) {
            result.qword += RdValue ;
            // EMU_CLK += CLK_CONT.I() ;
        } // if constexpr

        if constexpr (S) {
            TestBit(result.qword, 63) ? instance._status.SetN() : instance._status.ClearN()  ;
            result.qword == 0 ? instance._status.SetZ() : instance._status.ClearZ();
        } // if constexpr

        CPU_REG[RdLoNumber] = result.dword[0] ;
        CPU_REG[RdHiNumber] = result.dword[1] ;
    }
}

#endif //ARM_ANALYZER_V4_MULTIPLY_API_H

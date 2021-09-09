 //
// Created by jason4_lee on 2020-10-06.
//

#include <bit_manipulate.h>

#ifndef ARM_ANALYZER_V4_MULTIPLY_API_H
#define ARM_ANALYZER_V4_MULTIPLY_API_H

namespace gg_core::gg_cpu {
    template <bool S>
    static uint32_t ALU_Multiply(CPU& instance, uint32_t arg1, uint32_t arg2) {
        unsigned boothValue = 4;
        for (int i = 1; i < 4; ++i) {
            unsigned boothCheck = arg2 >> (8 * i);
            const uint32_t allOneMask = 0xffffffff;
            if (boothCheck == 0 || boothCheck == allOneMask >> (8 * i)) {
                boothValue = i;
                break;
            } // if
        } // for

        uint32_t result = arg1 * arg2 ;
        instance.cycle += boothValue ; // The I_Cycle cycle

        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4,gg_mem::S_Cycle) ;

        if constexpr (S) {
            // Result of C is meaningless, V is unaffected.
            result == 0 ? instance.SetZ() : instance.ClearZ();
            TestBit(result, 31) ? instance.SetN() : instance.ClearN();
        } // if

        return result ;
    } // ALU_Multiply()

    template<bool A, bool S>
    static void Multiply_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::I_Cycle) ;

        uint8_t RsNumber = BitFieldValue<8, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RdNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RmNumber = BitFieldValue<0, 4>(CURRENT_INSTRUCTION) ;

        unsigned RsValue = instance._regs[ RsNumber ] ;
        unsigned RmValue = instance._regs[ RmNumber ] ;

        uint32_t result = ALU_Multiply<S>(instance, RmValue, RsValue) ;

        if constexpr (A) {
            uint8_t RnNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION);
            unsigned RnValue = instance._regs[ RnNumber ] ;
            result += RnValue ;
            instance.cycle += 1 ; // The I_Cycle cycle
        } // if

        instance._regs[RdNumber] = result ;
//        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4,gg_mem::S_Cycle) ; // move to ALU_Multiply()
    } // Multiply()

    template<bool U, bool A, bool S>
    static void MultiplyLong_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::I_Cycle) ;

        uint32_t RsVal = instance._regs[BitFieldValue<8, 4>(CURRENT_INSTRUCTION)] ;
        uint32_t RmVal = instance._regs[BitFieldValue<0, 4>(CURRENT_INSTRUCTION)] ;

        uint8_t RdLoNumber = BitFieldValue<12, 4>(CURRENT_INSTRUCTION) ;
        uint8_t RdHiNumber = BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ;

        union Mull_t {
            uint64_t qword ;
            uint32_t dword[2] ;
            Mull_t(uint64_t val) {qword = val;}
        };

        Mull_t result = 0 ;
        if constexpr (U) {
            const int64_t signedRs = (static_cast<int64_t>(RsVal) << 32) >> 32;
            const int64_t signedRm = (static_cast<int64_t>(RmVal) << 32) >> 32;
            result = signedRm * signedRs;
        } // if
        else
            result = static_cast<uint64_t>(RsVal)*RmVal ;

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

        instance.cycle += boothValue + 1 ;

        if constexpr (A) {
            uint64_t RdValue = (static_cast<uint64_t>(CPU_REG[RdHiNumber]) << 32) | CPU_REG[RdLoNumber] ;
            result.qword += RdValue ;
            instance.cycle += 1 ;
            // EMU_CLK += CLK_CONT.I_Cycle() ;
        } // if constexpr

        if constexpr (S) {
            TestBit(result.qword, 63) ? instance.SetN() : instance.ClearN()  ;
            result.qword == 0 ? instance.SetZ() : instance.ClearZ();
        } // if constexpr

        CPU_REG[RdLoNumber] = result.dword[0] ;
        CPU_REG[RdHiNumber] = result.dword[1] ;

        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4,gg_mem::S_Cycle) ;
    }
}

#endif //ARM_ANALYZER_V4_MULTIPLY_API_H

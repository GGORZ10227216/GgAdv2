//
// Created by jason4_lee on 2020-09-28.
//

#include <cstdint>
#include <cstring>
#include <v4_operand2.h>

#ifndef GGADV2_MEM_API_H
#define GGADV2_MEM_API_H

namespace gg_core::gg_cpu {
    template <bool I_Cycle, bool P, bool U, bool B, bool W, bool L, SHIFT_TYPE ST>
    static void SingleDataTransfer_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::N_Cycle) ;

        constexpr bool translation = !P && W ;

        uint8_t RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ;
        uint8_t RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ;

        auto Access = [&]() {
            uint32_t &Rn = instance._regs[ RnNumber ] ;
            uint32_t &Rd = instance._regs[ RdNumber ] ;
            uint32_t offset = 0, targetAddr = Rn ;

            if constexpr (I_Cycle) {
                ParseOp2_Shift_Imm<ST>(instance, offset) ;
            } // constexpr()
            else {
                offset = CURRENT_INSTRUCTION & 0xfff ;
            } // else

            auto calculateTargetAddr = [&]() {
                if constexpr (U)
                    targetAddr += offset ;
                else
                    targetAddr -= offset ;
            };

            if constexpr (L) {
                // ldr
                if constexpr (P)
                    calculateTargetAddr() ;

                if constexpr (B) {
                    Rd = instance._mem.Read<uint8_t>(targetAddr, gg_mem::I_Cycle) ;
                } // if
                else {
                    Rd = instance._mem.Read<uint32_t>(targetAddr, gg_mem::I_Cycle) ;
                } // else

                if (RdNumber == pc) {
                    instance._mem.Read<uint32_t>(instance._regs[ gg_cpu::pc ] + 4, gg_mem::N_Cycle) ;
                    instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
                } // if
                else {
                    instance._mem.Read<uint32_t>(instance._regs[ gg_cpu::pc ] + 4, gg_mem::S_Cycle) ;
                } // else


                if constexpr (!P || W) {
                    // Info from heyrick.eu:
                    //      Pre-indexed (any) / Post-indexed (any): Using the same register as Rd and Rn is unpredictable.
                    if (RnNumber != RdNumber) {
                        if constexpr (!P)
                            calculateTargetAddr() ;
                        Rn = targetAddr ;
                    } // if
                } // if
            } // if
            else {
                // str
                if constexpr (P)
                    calculateTargetAddr() ;

                if constexpr (B) {
                    if (RdNumber == pc)
                        instance._mem.Write<uint8_t>(targetAddr, static_cast<uint8_t>(Rd + 4), gg_mem::N_Cycle) ;
                    else
                        instance._mem.Write<uint8_t>(targetAddr, static_cast<uint8_t>(Rd), gg_mem::N_Cycle) ;
                } // if
                else {
                    if (RdNumber == pc)
                        instance._mem.Write<uint32_t>(targetAddr, Rd + 4, gg_mem::N_Cycle) ;
                    else
                        instance._mem.Write<uint32_t>(targetAddr, Rd, gg_mem::N_Cycle) ;
                } // else

                if constexpr (!P || W) {
                    // Info from heyrick.eu:
                    //      Pre-indexed (any) / Post-indexed (any): Using the same register as Rd and Rn is unpredictable.
                    if constexpr (!P)
                        calculateTargetAddr() ;
                    Rn = targetAddr ;
                } // if
            } // else
        };

        if constexpr (translation)
            instance.AccessUsrRegBankInPrivilege(Access) ;
        else
            Access() ;
    } // MemAccess_impl()

    template <bool P, bool U, bool W, bool L, bool S, bool H,  OFFSET_TYPE OT>
    void HalfMemAccess_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::N_Cycle) ;

        unsigned int RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ;
        unsigned int RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ;
        uint32_t &Rn = instance._regs[ RnNumber ] ;
        uint32_t &Rd = instance._regs[ RdNumber ] ;
        uint32_t offset = 0, targetAddr = Rn ;

        if constexpr (OT == OFFSET_TYPE::RM) {
            offset = instance._regs[ CURRENT_INSTRUCTION & 0xf ] ;
        } // constexpr()
        else {
            offset = ((CURRENT_INSTRUCTION & 0xf00) >> 4) | (CURRENT_INSTRUCTION & 0xf) ;
        } // else

        auto calculateTargetAddr = [&]() {
            if constexpr (U)
                targetAddr += offset ;
            else
                targetAddr -= offset ;
        };

        if constexpr (L) {
            // ldr
            if constexpr (P)
                calculateTargetAddr() ;

            if constexpr (!S && !H)
                gg_core::Unreachable() ;
            else if constexpr (!S && H) {
                // LDRH
                Rd = instance._mem.Read<uint16_t>(targetAddr, gg_mem::I_Cycle) ;
            } // else if
            else if constexpr (S && !H) {
                // LDRSB
                Rd = (static_cast<int32_t>(instance._mem.Read<uint8_t>(targetAddr, gg_mem::I_Cycle)) << 24) >> 24 ; // sign extend
            } // else if
            else {
                // LDRSH
                /// fixme: need rotate?
                const unsigned extShiftAmount = targetAddr & 1 ? 24 : 16 ;
                Rd = (static_cast<int32_t>(instance._mem.Read<uint16_t>(targetAddr, gg_mem::I_Cycle)) << extShiftAmount) >> extShiftAmount ; // sign extend
            } // else

            if (RdNumber == pc) {
                if constexpr (H)
                    instance._mem.Read<uint16_t>(instance._regs[ gg_cpu::pc ] + 4, gg_mem::N_Cycle) ;
                else
                    instance._mem.Read<uint8_t>(instance._regs[ gg_cpu::pc ] + 4, gg_mem::N_Cycle) ;

                instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
            } // if
            else {
                instance._mem.Read<uint16_t>(instance._regs[ gg_cpu::pc ] + 4, gg_mem::S_Cycle) ;
            } // else

            if constexpr (!P || W) {
                if constexpr (!P)
                    calculateTargetAddr() ;
                if (RdNumber != RnNumber)
                    Rn = targetAddr ;
            } // if
        } // if
        else {
            // str
            if constexpr (P)
                calculateTargetAddr() ;

            if constexpr (!S && H) {
                // STRH
                if (RdNumber == gg_cpu::pc)
                    instance._mem.Write<uint16_t>(targetAddr, static_cast<uint16_t>(Rd + 4), gg_mem::N_Cycle) ;
                else
                    instance._mem.Write<uint16_t>(targetAddr, static_cast<uint16_t>(Rd), gg_mem::N_Cycle) ;
            } // else if
            else
                gg_core::Unreachable();

            if constexpr (!P || W) {
                if constexpr (!P)
                    calculateTargetAddr() ;
                Rn = targetAddr ;
            } // if
        } // else
    } // HalfMemAccess_impl()

    template <bool P, bool U, bool S, bool W, bool L>
    void BlockMemAccess_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::N_Cycle) ;

        // todo: undocumented behavior of ldm/stm implement
        uint32_t regList = BitFieldValue<0, 16>(CURRENT_INSTRUCTION) ;
        uint32_t &Rn = instance._regs[ BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ] ;

        uint32_t base = 0 ;
        unsigned int registerCnt = PopCount32(regList) ;
        uint32_t offset = registerCnt * 4 ;

        if (registerCnt == 0) {
            regList = 0x8000 ; // pc only
            offset = 0x40 ;
        } // if

        uint32_t originalCPSR = instance.ReadCPSR() ;
        uint32_t originalMode = instance.GetOperationMode() ;

        if constexpr (S)
            instance.WriteCPSR( (originalCPSR & ~0b11111) | static_cast<uint32_t>(E_OperationMode::USR) ) ;

        if constexpr (U) {
            if constexpr (P) {
                // pre-increment
                base = Rn + 4 ;
            } // if
            else {
                // post-increment
                base = Rn ;
            } // else
        } // if
        else {
            if constexpr (P) {
                // pre-decrement
                base = Rn - offset ;
            } // if
            else {
                // post-decrement
                base = Rn - offset + 4 ;
            } // else
        } // else

        for (size_t idx = 0 ; idx < 16 ; ++idx) {
            if (TestBit(regList, idx)) {
                if constexpr (L) {
                    const auto cycleType = --registerCnt == 0 ? gg_mem::I_Cycle : gg_mem::S_Cycle ;
                    CPU_REG[ idx ] = instance._mem.Read<uint32_t>(base, cycleType) ;

                    if (idx == pc) {
                        CPU_REG[ pc ] &= ~0x3 ;
                        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4, gg_mem::N_Cycle) ;
                        instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
                    } // if
                    else {
                        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4, gg_mem::S_Cycle) ;
                    } // else
                } // if
                else {
                    const auto cycleType = --registerCnt == 0 ? gg_mem::N_Cycle : gg_mem::S_Cycle ;
                    uint32_t regVal = CPU_REG[ idx ] ;
                    if (idx == 15)
                        regVal = (regVal + 4) & ~0x3 ;
                    instance._mem.Write<uint32_t>(base, regVal, cycleType) ;
                } // else

                base += 4 ;
            } // if
        } // for

        if constexpr (S) {
            if constexpr (L) {
                if (TestBit(regList, 15))
                    instance.WriteCPSR(instance.ReadSPSR(static_cast<E_OperationMode>(originalMode))) ;
            } // if

            instance.WriteCPSR( (originalCPSR & ~0b11111) | originalMode ) ;
        } // if

        if constexpr (W) {
            if constexpr (U)
                Rn += offset ;
            else
                Rn -= offset ;
        } // if
    } // BlockMemAccess_impl()

    template <bool B>
    void Swap_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::N_Cycle) ;

        uint32_t Rn = instance._regs[ (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ] ;
        uint32_t &Rd = instance._regs[ (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ] ;
        uint32_t Rm = instance._regs[ CURRENT_INSTRUCTION & 0xf ] ;

        if constexpr (B) {
            Rd = instance._mem.Read<uint8_t>(Rn, gg_mem::N_Cycle) ;
            instance._mem.Write<uint8_t>(Rn, static_cast<uint8_t>(Rm), gg_mem::I_Cycle) ;
        } // if
        else {
            Rd = instance._mem.Read<uint32_t>(Rn, gg_mem::N_Cycle) ;
            instance._mem.Write<uint32_t>(Rn, Rm, gg_mem::I_Cycle) ;
        } // if

        instance._mem.Read<uint32_t>(CPU_REG[ pc ] + 4, gg_mem::N_Cycle) ;
    } // Swap_impl()
}

#endif //GGADV2_MEM_API_H

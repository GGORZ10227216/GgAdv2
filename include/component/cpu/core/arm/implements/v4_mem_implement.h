//
// Created by jason4_lee on 2020-09-28.
//

#include <cstdint>
#include <v4_operand2.h>

#ifndef GGADV2_MEM_API_H
#define GGADV2_MEM_API_H

namespace gg_core::gg_cpu {
    template <bool I, bool P, bool U, bool B, bool W, bool L, SHIFT_TYPE ST>
    static void SingleDataTransfer_impl(GbaInstance &instance) {
        // todo: Rd == r15 behavior
        // todo: LDRT support is done, but still not tested.

        constexpr bool translation = !P && W ;

        uint8_t RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ;
        uint8_t RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ;

        auto Access = [&]() {
            uint32_t &Rn = instance._status._regs[ RnNumber ] ;
            uint32_t &Rd = instance._status._regs[ RdNumber ] ;
            uint32_t offset = 0, targetAddr = Rn ;

            if constexpr (I) {
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
                    Rd = instance._mem.Read8(targetAddr) ;
                } // if
                else {
                    Rd = instance._mem.Read32(targetAddr) ;
                } // else

                if (RdNumber == pc)
                    instance.RefillPipeline() ;

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
                        instance._mem.Write8(targetAddr, static_cast<uint8_t>(Rd + 4)) ;
                    else
                        instance._mem.Write8(targetAddr, static_cast<uint8_t>(Rd)) ;
                } // if
                else {
                    if (RdNumber == pc)
                        instance._mem.Write32(targetAddr, Rd + 4) ;
                    else
                        instance._mem.Write32(targetAddr, Rd) ;
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
            instance._status.AccessUsrRegBankInPrivilege(Access) ;
        else
            Access() ;
    } // MemAccess_impl()

    template <bool P, bool U, bool W, bool L, bool S, bool H,  OFFSET_TYPE OT>
    void HalfMemAccess_impl(GbaInstance &instance) {
        // todo: Rd == r15 behavior
        unsigned int RnNumber = (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ;
        unsigned int RdNumber = (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ;
        uint32_t &Rn = instance._status._regs[ RnNumber ] ;
        uint32_t &Rd = instance._status._regs[ RdNumber ] ;
        uint32_t offset = 0, targetAddr = Rn ;

        if constexpr (OT == OFFSET_TYPE::RM) {
            offset = instance._status._regs[ CURRENT_INSTRUCTION & 0xf ] ;
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
                Rd = instance._mem.Read16(targetAddr) ;
                if (RdNumber == pc)
                    instance.RefillPipeline() ;
            } // else if
            else if constexpr (S && !H) {
                // LDRSB
                Rd = (static_cast<int32_t>(instance._mem.Read8(targetAddr)) << 24) >> 24 ; // sign extend
                if (RdNumber == pc)
                    instance.RefillPipeline() ;
            } // else if
            else {
                // LDRSH
                Rd = (static_cast<int32_t>(instance._mem.Read16(targetAddr)) << 16) >> 16 ; // sign extend
                if (RdNumber == pc)
                    instance.RefillPipeline() ;
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
                    instance._mem.Write16(targetAddr, static_cast<uint16_t>(Rd + 4)) ;
                else
                    instance._mem.Write16(targetAddr, static_cast<uint16_t>(Rd)) ;
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
    void BlockMemAccess_impl(GbaInstance &instance) {
        // todo: undocumented behavior of ldm/stm implement
        uint32_t regList = BitFieldValue<0, 16>(CURRENT_INSTRUCTION) ;
        uint32_t &Rn = instance._status._regs[ BitFieldValue<16, 4>(CURRENT_INSTRUCTION) ] ;

        uint32_t base = 0 ;
        uint32_t offset = PopCount32(regList)*4 ;

        uint32_t originalCPSR = instance._status.ReadCPSR() ;
        uint32_t originalMode = instance._status.GetOperationMode() ;

        if constexpr (S)
            instance._status.WriteCPSR( (originalCPSR & ~0b11111) | static_cast<uint32_t>(E_OperationMode::USR) ) ;

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
                    CPU_REG[ idx ] = instance._mem.Read32(base) ;
                } // if
                else {
                    uint32_t regVal = CPU_REG[ idx ] ;
                    if (idx == 15)
                        regVal += 4 ;
                    instance._mem.Write32(base, regVal) ;
                } // else

                base += 4 ;
            } // if
        } // for

        if constexpr (S) {
            if constexpr (L) {
                if (TestBit(regList, 15))
                    instance._status.WriteCPSR(instance._status.ReadSPSR(static_cast<E_OperationMode>(originalMode))) ;
            } // if

            instance._status.WriteCPSR( (originalCPSR & ~0b11111) | originalMode ) ;
        } // if

        if constexpr (W) {
            if constexpr (U)
                Rn += offset ;
            else
                Rn -= offset ;
        } // if
    } // BlockMemAccess_impl()

    template <bool B>
    void Swap_impl(GbaInstance &instance) {
        uint32_t Rn = instance._status._regs[ (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ] ;
        uint32_t &Rd = instance._status._regs[ (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ] ;
        uint32_t Rm = instance._status._regs[ CURRENT_INSTRUCTION & 0xf ] ;

        if constexpr (B) {
            Rd = instance._mem.Read8(Rn) ;
            instance._mem.Write8(Rn, static_cast<uint8_t>(Rm)) ;
        } // if
        else {
            Rd = instance._mem.Read32(Rn) ;
            instance._mem.Write32(Rn, Rm) ;
        } // if
    } // Swap_impl()
}

#endif //GGADV2_MEM_API_H

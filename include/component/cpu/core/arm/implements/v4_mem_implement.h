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
        uint32_t immOffset = 0 ;
        uint32_t &Rn = instance._status._regs[ (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ] ;
        uint32_t &Rd = instance._status._regs[ (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ] ;
        auto writeBack = [&]() {
            if constexpr (U)
                Rn += immOffset ;
            else
                Rn -= immOffset ;
        };

        if constexpr (I) {
            immOffset = CURRENT_INSTRUCTION & 0xfff ;
        } // constexpr()
        else {
            ParseOp2_Shift_Imm<ST>(instance, immOffset) ;
        } // else

        if constexpr (L) {
            // ldr
            if constexpr (P && W) {
                writeBack() ;
            } // if

            if constexpr (B) {
                Rd = instance._mem.Read8(Rn) ;
            } // if
            else {
                Rd = instance._mem.Read32(Rn) ;
            } // else

            if constexpr (!P && W) {
                writeBack() ;
            } // if
        } // if
        else {
            // str
            if constexpr (P && W) {
                writeBack() ;
            } // if

            if constexpr (B) {
                instance._mem.Write8(Rn, static_cast<uint8_t>(Rd)) ;
            } // if
            else {
                instance._mem.Write32(Rn, Rd) ;
            } // else

            if constexpr (!P && W) {
                writeBack() ;
            } // if
        } // else
    } // MemAccess_impl()



    template <bool P, bool U, bool W, bool L, bool S, bool H,  OFFSET_TYPE OT>
    void HalfMemAccess_impl(GbaInstance &instance) {
        // todo: Rd == r15 behavior
        uint32_t offset = 0 ;
        uint32_t &Rn = instance._status._regs[ (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ] ;
        uint32_t &Rd = instance._status._regs[ (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ] ;
        auto writeBack = [&]() {
            if constexpr (U)
                Rn += offset ;
            else
                Rn -= offset ;
        };

        if constexpr (OT == OFFSET_TYPE::RM) {
            offset = instance._status._regs[ CURRENT_INSTRUCTION & 0xf ] ;
        } // constexpr()
        else {
            offset = ((CURRENT_INSTRUCTION & 0xf00) >> 4) | (CURRENT_INSTRUCTION & 0xf) ;
        } // else

        if constexpr (L) {
            // ldr
            if constexpr (P && W) {
                writeBack() ;
            } // if

            if constexpr (!S && H) {
                // LDRH
                Rd = instance._mem.Read16(Rn) ;
            } // else if
            else if constexpr (S && !H) {
                // LDRSB
                Rd = instance._mem.Read8(Rn) ;
                if (TestBit(Rd, 7))
                    Rd |= 0xffffff00 ; // sign extend
            } // else if
            else {
                // LDRSH
                Rd = instance._mem.Read16(Rn) ;
                if (TestBit(Rd, 15))
                    Rd |= 0xffff0000 ; // sign extend
            } // else

            if constexpr (!P && W) {
                writeBack() ;
            } // if
        } // if
        else {
            // str
            if constexpr (P && W) {
                writeBack() ;
            } // if

            if constexpr (!S && H) {
                // STRH
                instance._mem.Write16(Rn, static_cast<uint16_t>(Rd)) ;
            } // else if
            else {
                static_assert( true, "unknown parameters" );
            }

            if constexpr (!P && W) {
                writeBack() ;
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

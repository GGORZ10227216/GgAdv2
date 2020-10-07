//
// Created by jason4_lee on 2020-09-28.
//

#include <cstdint>
#include <instruction/arm/api/v4_alu_api.h>

#ifndef GGADV2_MEM_API_H
#define GGADV2_MEM_API_H

namespace gg_core::gg_cpu {
    template <bool I, bool P, bool U, bool B, bool W, bool L, SHIFT_TYPE ST>
    void MemAccess_impl(GbaInstance &instance) {
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

    enum class OFFSET_TYPE { RM, IMM };

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

    template <bool B>
    void Swap(GbaInstance &instance) {
        uint32_t &Rn = instance._status._regs[ (CURRENT_INSTRUCTION & 0xf'0000) >> 16 ] ;
        uint32_t &Rd = instance._status._regs[ (CURRENT_INSTRUCTION & 0x0'f000) >> 12 ] ;
        uint32_t &Rm = instance._status._regs[ CURRENT_INSTRUCTION & 0xf ] ;

        if constexpr (B) {
            Rd = instance._mem.Read8(Rn) ;
            instance._mem.Write8(Rn, static_cast<uint8_t>(Rm)) ;
        } // if
        else {
            Rd = instance._mem.Read32(Rn) ;
            instance._mem.Write32(Rn, Rm) ;
        } // if
    }
}

#endif //GGADV2_MEM_API_H

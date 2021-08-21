#include <cstdint>

#ifndef V4_ARM_PSR_TRANSFER
#define V4_ARM_PSR_TRANSFER

namespace gg_core::gg_cpu {
    static void mrs(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;

        const uint32_t RdNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t &Rd = instance._regs[RdNumber] ;
        Rd = instance.ReadCPSR() ;
    }

    static void msr_Rm(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;

        const uint32_t RmNumber = CURRENT_INSTRUCTION & 0xf;
        uint32_t Rm = instance._regs[RmNumber] ;
        if (instance.GetOperationMode() == USR || !TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedCpsr = instance.ReadCPSR() & 0x0fffffff ;
            uint32_t newCpsrValue = protectedCpsr | (Rm & 0xf0000000) ;
            instance.WriteCPSR(newCpsrValue) ;
        } // if
        else {
            instance.WriteCPSR(Rm) ;
        } // else
    }

    static void mrsp(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;

        const uint32_t RdNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t &Rd = instance._regs[RdNumber] ;
        Rd = instance.ReadSPSR() ;
    }

    static void msrp_Rm(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;

        const uint32_t RmNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t Rm = instance._regs[RmNumber] ;
        if (!TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedSpsr = instance.ReadSPSR() & 0x0fffffff ;
            uint32_t newSpsrValue = protectedSpsr | (Rm & 0xf0000000) ;
            instance.WriteSPSR(newSpsrValue) ;
        } // if
        else {
            instance.WriteSPSR(Rm) ;
        } // else
    }

    static void msr_Imm(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;

        const uint32_t imm = CURRENT_INSTRUCTION & 0xff;
        const uint32_t rot = (CURRENT_INSTRUCTION & 0xf00) >> 8;
        const uint32_t immVal = rotr(imm, rot*2) ;

        if (instance.GetOperationMode() == USR || !TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedCpsr = instance.ReadCPSR() & 0x0fffffff ;
            uint32_t newCpsrValue = protectedCpsr | (immVal & 0xf0000000) ;
            instance.WriteCPSR(newCpsrValue) ;
        } // if
        else {
            instance.WriteCPSR(immVal) ;
        } // else
    }

    static void msrp_Imm(CPU& instance) {
        instance.Fetch(&instance, gg_mem::S_Cycle) ;
        
        const uint32_t imm = CURRENT_INSTRUCTION & 0xff;
        const uint32_t rot = (CURRENT_INSTRUCTION & 0xf00) >> 8;
        const uint32_t immVal = rotr(imm, rot*2) ;

        if (!TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedSpsr = instance.ReadSPSR() & 0x0fffffff ;
            uint32_t newSpsrValue = protectedSpsr | (immVal & 0xf0000000) ;
            instance.WriteSPSR(newSpsrValue) ;
        } // if
        else {
            instance.WriteSPSR(immVal) ;
        } // else
    }
} // gg_core::gg_cpu

# endif // V4_ARM_PSR_TRANSFER
namespace gg_core::gg_cpu {
    static void mrs(GbaInstance& instance) {
        const uint32_t RdNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t &Rd = instance._status._regs[RdNumber] ;
        Rd = instance._status.ReadCPSR() ;
    }

    static void msr_Rm(GbaInstance& instance) {
        const uint32_t RmNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t Rm = instance._status._regs[RmNumber] ;
        if (instance._status.GetOperationMode() == USR || !TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedCpsr = instance._status.ReadCPSR() & 0x0fffffff ;
            uint32_t newCpsrValue = protectedCpsr | (Rm & 0xf0000000) ;
            instance._status.WriteCPSR(newCpsrValue) ;
        } // if
        else {
            instance._status.WriteCPSR(Rm) ;
        } // else
    }

    static void mrsp(GbaInstance& instance) {
        const uint32_t RdNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t &Rd = instance._status._regs[RdNumber] ;
        Rd = instance._status.ReadSPSR() ;
    }

    static void msrp_Rm(GbaInstance& instance) {
        const uint32_t RmNumber = (CURRENT_INSTRUCTION & 0xf000) >> 12 ;
        uint32_t Rm = instance._status._regs[RmNumber] ;
        if (!TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedSpsr = instance._status.ReadSPSR() & 0x0fffffff ;
            uint32_t newSpsrValue = protectedSpsr | (Rm & 0xf0000000) ;
            instance._status.WriteSPSR(newSpsrValue) ;
        } // if
        else {
            instance._status.WriteSPSR(Rm) ;
        } // else
    }

    static void msr_Imm(GbaInstance& instance) {
        const uint32_t imm = CURRENT_INSTRUCTION & 0xff;
        const uint32_t rot = (CURRENT_INSTRUCTION & 0xf00) >> 8;
        const uint32_t immVal = rotr(imm, rot*2) ;

        if (instance._status.GetOperationMode() == USR || !TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedCpsr = instance._status.ReadCPSR() & 0x0fffffff ;
            uint32_t newCpsrValue = protectedCpsr | (immVal & 0xf0000000) ;
            instance._status.WriteCPSR(newCpsrValue) ;
        } // if
        else {
            instance._status.WriteCPSR(immVal) ;
        } // else
    }

    static void msrp_Imm(GbaInstance& instance) {
        const uint32_t imm = CURRENT_INSTRUCTION & 0xff;
        const uint32_t rot = (CURRENT_INSTRUCTION & 0xf00) >> 8;
        const uint32_t immVal = rotr(imm, rot*2) ;

        if (!TestBit(CURRENT_INSTRUCTION, 16)) {
            uint32_t protectedSpsr = instance._status.ReadSPSR() & 0x0fffffff ;
            uint32_t newSpsrValue = protectedSpsr | (immVal & 0xf0000000) ;
            instance._status.WriteSPSR(newSpsrValue) ;
        } // if
        else {
            instance._status.WriteSPSR(immVal) ;
        } // else
    }

    template <uint32_t HashCode32>
    void PSR_Transfer(GbaInstance &instance) {
        if constexpr (BitFieldValue<20,2>(HashCode32) == 0b00) {
            // MRS
            if constexpr (TestBit(HashCode32, 22))
                mrsp(instance) ;
            else
                mrs(instance);
        } // if
        else if constexpr (BitFieldValue<20,2>(HashCode32) == 0b10) {
            // MSR
            if constexpr (TestBit(HashCode32, 25)) {
                if constexpr (TestBit(HashCode32, 22))
                    msrp_Imm(instance);
                else
                    msr_Imm(instance);
            } // if
            else {
                if constexpr (TestBit(HashCode32, 22))
                    msrp_Rm(instance);
                else
                    msr_Rm(instance);
            } // else
        } // else
        else
            __builtin_unreachable() ;
    } // PSR_Transfer()
} // gg_core::gg_cpu

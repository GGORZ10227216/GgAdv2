namespace gg_core::gg_cpu {
    static void BranchExchange_impl(GbaInstance& instance) {
        const uint32_t RnNumber = instance._status.CurrentInstruction() & 0xf ;
        uint32_t &Rn = instance._status._regs[RnNumber] ;

        if (Rn & 0x1)
            instance._status.ChangeCpuMode(THUMB) ;
        else
            instance._status.ChangeCpuMode(ARM) ;

        instance._status._regs[pc] = Rn ;
        instance.RefillPipeline() ;
    }

    template <bool L>
    static void Branch_impl(GbaInstance& instance) {
        int32_t offset = (instance._status.CurrentInstruction() & 0x00ffffff) << 2;

        if (gg_core::TestBit(offset, 25))
            offset |= 0xfc000000 ; // sign extend

        if constexpr (L)
            instance._status._regs[lr] = instance._status._regs[pc] - 4 ;

        instance._status._regs[pc] += offset ;
        instance.RefillPipeline() ;
    }
} // gg_core::gg_cpu

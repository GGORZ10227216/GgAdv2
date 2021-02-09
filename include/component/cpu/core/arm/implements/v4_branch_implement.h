namespace gg_core::gg_cpu {
    static void BranchExchange_impl(CPU& instance) {
        const uint32_t RnNumber = instance.CurrentInstruction() & 0xf ;
        uint32_t &Rn = instance._regs[RnNumber] ;

        if (Rn & 0x1)
            instance.ChangeCpuMode(THUMB) ;
        else
            instance.ChangeCpuMode(ARM) ;

        instance._regs[pc] = Rn ;
        instance.RefillPipeline();
    }

    template <bool L>
    static void Branch_impl(CPU& instance) {
        int32_t offset = (instance.CurrentInstruction() & 0x00ffffff) << 2;

        if (gg_core::TestBit(offset, 25))
            offset |= 0xfc000000 ; // sign extend

        if constexpr (L)
            instance._regs[lr] = instance._regs[pc] - 4 ;

        instance._regs[pc] += offset ;
        instance.RefillPipeline();
    }
} // gg_core::gg_cpu

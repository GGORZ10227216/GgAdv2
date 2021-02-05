namespace gg_core::gg_cpu {
    static void BranchExchange_impl(CPUCore& self) {
        const uint32_t RnNumber = self.CurrentInstruction() & 0xf ;
        uint32_t &Rn = self._regs[RnNumber] ;

        if (Rn & 0x1)
            self.ChangeCpuMode(THUMB) ;

        self._regs[pc] = Rn ;
        self.RefillPipeline<ARM>() ;
    }

    template <bool L>
    static void Branch_impl(CPUCore& self) {
        int32_t offset = (self.CurrentInstruction() & 0x00ffffff) << 2;

        if (gg_core::TestBit(offset, 25))
            offset |= 0xfc000000 ; // sign extend

        if constexpr (L)
            self._regs[lr] = self._regs[pc] - 4 ;

        self._regs[pc] += offset ;
        self.RefillPipeline<ARM>() ;
    }
} // gg_core::gg_cpu

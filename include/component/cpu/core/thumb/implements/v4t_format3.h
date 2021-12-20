//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT3_H
#define GGTEST_V4T_FORMAT3_H

namespace gg_core::gg_cpu {
    using namespace gg_core::gg_mem ;

    template <E_DataProcess OP>
    extern void MovCmpAddSub(CPU& instance) {
        /**
         * Remove Rd in template argument,
         *
         * Even if we can get targetRd In instruction hash, we should not use it as a template
         * to access CPU's registers.
         * Because it will create a lot of jmp instruction, and this is cache unfriendly.
         **/
        instance.Fetch(&instance, S_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        const unsigned offset8 = curInst & 0xff ;
        const unsigned targetRd = (curInst & 0x700) >> 8 ;
        const uint32_t RdValue = instance._regs[ targetRd ] ;

        uint32_t result = ALU_Calculate<true, OP>(instance, RdValue, offset8, false) ;

        if constexpr (OP != E_DataProcess::CMP)
            instance._regs[ targetRd ] = result ;
    } // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT3_H

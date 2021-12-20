//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT11_H
#define GGTEST_V4T_FORMAT11_H

namespace gg_core::gg_cpu {
    template <bool L>
    extern void SP_RelativeLoadStore(CPU& instance) {
        instance.Fetch(&instance, N_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        const unsigned targetRd = (curInst & (0b111 << 8)) >> 8 ;
        const unsigned offsetImm = (curInst & 0xff) << 2 ; // 10 bit offset

        const unsigned targetAddr = instance._regs[ sp ] + offsetImm;

        if constexpr (L) {
            MemLoad<uint32_t, false>(instance, targetAddr, targetRd) ;
        } // if
        else {
            MemStore<uint32_t>(instance, targetAddr, targetRd) ;
        } // else
    } // SP_RelativeLoadStore()
}

#endif //GGTEST_V4T_FORMAT11_H

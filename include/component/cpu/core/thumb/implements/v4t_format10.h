//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT10_H
#define GGTEST_V4T_FORMAT10_H

namespace gg_core::gg_cpu {
    template <bool L>
    static void LoadStoreImmOffsetHalf(CPU& instance) {
        instance.Fetch(&instance, N_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        const unsigned targetRd = curInst & 0b111;
        const unsigned baseReg   = (curInst & (0b111 << 3)) >> 3 ;
        const unsigned offsetImm = (curInst & (0b11111 << 6)) >> 5 ;

        const unsigned targetAddr = instance._regs[ baseReg ] + offsetImm;

        if constexpr (L) {
            MemLoad<uint16_t, false>(instance, targetAddr, targetRd) ;
        } // if
        else {
            MemStore<uint16_t>(instance, targetAddr, targetRd) ;
        } // else
    } // LoadStoreRegOffsetSignEx()
}

#endif //GGTEST_V4T_FORMAT10_H

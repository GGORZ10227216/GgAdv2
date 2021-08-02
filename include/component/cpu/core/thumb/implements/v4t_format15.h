//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT15_H
#define GGTEST_V4T_FORMAT15_H

namespace gg_core::gg_cpu {
    template <bool L>
    static void MultiLoadStore(CPU& instance) {
        instance.Fetch(&instance, N_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        unsigned baseReg = curInst & ((0b111 << 8)) >> 8 ;
        unsigned regList = curInst & 0xff ;

        LDSTM<L, false, true, true>(instance, instance._regs[baseReg], regList);
    } // SP_Offset()
}

#endif //GGTEST_V4T_FORMAT15_H

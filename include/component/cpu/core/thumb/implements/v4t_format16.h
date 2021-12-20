//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT16_H
#define GGTEST_V4T_FORMAT16_H

namespace gg_core::gg_cpu {
    extern void ConditionalBranch(CPU& instance) {
        const uint16_t curInst = CURRENT_INSTRUCTION ;
        unsigned condition = curInst & ((0xf << 8)) >> 8 ;

        auto checker = instance.conditionChecker[ condition ] ;

        if ((instance.*checker)()) {
            instance.Fetch(&instance, N_Cycle) ;

            int16_t sOffset = (static_cast<int16_t>(curInst & 0xff) << 8) >> 8 ;

            instance._regs[pc] += sOffset ;
            instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
        } // if
        else
            instance.Fetch(&instance, S_Cycle) ;
    } // ConditionalBranch()
}

#endif //GGTEST_V4T_FORMAT16_H

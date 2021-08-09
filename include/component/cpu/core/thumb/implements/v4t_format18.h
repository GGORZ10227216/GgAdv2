//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT18_H
#define GGTEST_V4T_FORMAT18_H

namespace gg_core::gg_cpu {
    static void UnconditionalBranch(CPU& instance) {
        instance.Fetch(&instance, N_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        int offset = (static_cast<int16_t>(curInst & 0x7ff) << 5) >> 5 ;

        instance._regs[pc] += offset ;
        instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
    } // UnconditionalBranch()
}

#endif //GGTEST_V4T_FORMAT18_H

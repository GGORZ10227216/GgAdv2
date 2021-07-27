//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT5_H
#define GGTEST_V4T_FORMAT5_H

namespace gg_core::gg_cpu {
    template <auto OP, bool H1, bool H2>
    static void HiRegOperation_BX(CPU& instance) {
        const uint16_t curInst = CURRENT_INSTRUCTION ;
        unsigned targetRs = (curInst & 0b111000) >> 3;
        unsigned targetRd = curInst & 0b111 ;

        if constexpr (H1) targetRd += 8 ;
        if constexpr (H2) targetRs += 8;

        const uint32_t RsValue = instance._regs[ targetRs ] ;
        const uint32_t RdValue = instance._regs[ targetRd ] ;

        uint32_t result = 0 ;
        if constexpr (std::is_same_v<decltype(OP), E_DataProcess>) {
            instance.Fetch(&instance, S_Cycle) ;
            instance._regs[ targetRd ] = ALU_Calculate<true, OP>(instance, RdValue, RsValue, false)  ;
        } // if
        else {
            instance.Fetch(&instance, N_Cycle) ;
            BX(instance, targetRs);
        } // else

    } // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT5_H

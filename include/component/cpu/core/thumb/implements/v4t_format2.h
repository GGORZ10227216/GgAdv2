//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT2_H
#define GGTEST_V4T_FORMAT2_H

namespace gg_core::gg_cpu {
    using namespace gg_core::gg_mem ;

    template <bool IS_IMMEDIATE, E_DataProcess OPCODE>
    extern void AddSub(CPU& instance) {
        instance.Fetch(&instance, S_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;

        const unsigned targetRs = (curInst & 0b111000) >> 3 ;
        const unsigned targetRd = (curInst & 0b111) ;
        const unsigned offset = (curInst & (0b111 << 6)) >> 6 ;

        const uint32_t RsValue = instance._regs[ targetRs ] ;
        uint64_t result = 0 ;

        if constexpr (IS_IMMEDIATE)
            result = ALU_Calculate<true, OPCODE>(instance, RsValue, offset, false) ;
        else
            result = ALU_Calculate<true, OPCODE>(instance, RsValue, instance._regs[ offset ], false) ;

        instance._regs[ targetRd ] = result ;
    }
}

#endif //GGTEST_V4T_FORMAT2_H

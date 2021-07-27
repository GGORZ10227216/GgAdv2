//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT1_H
#define GGTEST_V4T_FORMAT1_H

namespace gg_core::gg_cpu {
    using namespace gg_core::gg_mem ;

    template <E_ShiftType ST>
    static void MoveShift(CPU& instance) {
        instance.Fetch(&instance, S_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;

        const unsigned targetRs = (curInst & 0b111000) >> 3 ;
        const unsigned targetRd = (curInst & 0b111) ;

        const uint32_t RsValue = instance._regs[ targetRs ] ;
        const unsigned shiftAmount = (curInst & (0b11111 << 6)) >> 6 ;

        uint32_t result = 0;
        if constexpr (ST == ROR)
            gg_core::Unreachable() ;
        bool shiftCarry = Op2ShiftImm<ST>(instance, result, RsValue, shiftAmount) ;

        // ALU_Calculate here is only for CPSR modification, no need to assign to result again.
        ALU_Calculate<true, E_DataProcess::MOV>(instance, RsValue, result, shiftCarry) ;
        instance._regs[ targetRd ] = result ;
    } // MoveShift()
}

#endif //GGTEST_V4T_FORMAT1_H

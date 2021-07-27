//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT4_H
#define GGTEST_V4T_FORMAT4_H

namespace gg_core::gg_cpu {
    template <auto OP>
    static void ALU_Operations(CPU& instance) {
        instance.Fetch(&instance, S_Cycle) ;

        const uint16_t curInst = CURRENT_INSTRUCTION ;
        const unsigned targetRs = (curInst & 0b111000) >> 3;
        const unsigned targetRd = curInst & 0b111 ;

        const uint32_t RsValue = instance._regs[ targetRs ] ;
        uint32_t RdValue = instance._regs[ targetRd ] ;

        uint32_t result = 0 ;
        if constexpr (std::is_same_v<decltype(OP), E_DataProcess>) {
            if constexpr (OP == RSB) // NEG <--> RSBS Rd, Rs, #0
                result = ALU_Calculate<true, OP>(instance, RsValue, 0, false) ;
            else
                result = ALU_Calculate<true, OP>(instance, RdValue, RsValue, false) ;
        } // if
        else if constexpr (std::is_same_v<decltype(OP), E_ShiftType>) {
            uint32_t shiftResult = 0 ;
            bool shiftCarry = Op2ShiftReg<OP>(instance, shiftResult, RdValue, RsValue) ;
            result = ALU_Calculate<true, E_DataProcess::MOV>(instance, RdValue, shiftResult, shiftCarry) ;
        } // else if
        else {
            result = ALU_Multiply<true>(instance, RsValue, RdValue) ;
        } // else

        instance._regs[ targetRd ] = result ;
    } // MovCmpAddSub()
}

#endif //GGTEST_V4T_FORMAT4_H

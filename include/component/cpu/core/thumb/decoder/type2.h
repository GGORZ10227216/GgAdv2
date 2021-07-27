//
// Created by orzgg on 2021-07-11.
//

#include <arm_encoder_v2.h>

#ifndef GGTEST_TYPE2_H
#define GGTEST_TYPE2_H

namespace gg_core::gg_cpu {
    template <uint32_t HashCode10>
    static constexpr auto ThumbType2() {
        constexpr unsigned opcode = (HashCode10 & (0b1 << 3)) >> 3 ;
        constexpr std::array<E_DataProcess, 2> type2Op {ADD, SUB} ;

        if constexpr (HashCode10 & (0b1 << 4) >> 4) {
            constexpr uint32_t equivalentArmCode = MakeALUInstruction(
                    std::pair(op_filed::Cond(), AL),
                    std::pair(op_filed::Imm(), 0x0),
                    std::pair(op_filed::OpCode(), type2Op[opcode]),
                    std::pair(op_filed::S(), true)
            ) ;

            return DataProcessing<equivalentArmCode>();
        } // if
        else {
            constexpr uint32_t equivalentArmCode = MakeALUInstruction(
                    std::pair(op_filed::Cond(), AL),
                    std::pair(op_filed::OpCode(), type2Op[opcode]),
                    std::pair(op_filed::S(), true)
            ) ;

            return DataProcessing<equivalentArmCode>();
        } // else
    }
}

#endif //GGTEST_TYPE2_H

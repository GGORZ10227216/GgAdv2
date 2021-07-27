//
// Created by orzgg on 2021-07-11.
//

#include <arm_encoder_v2.h>

#ifndef GGTEST_TYPE3_H
#define GGTEST_TYPE3_H

namespace gg_core::gg_cpu {
    template <uint32_t HashCode10>
    static constexpr auto ThumbType3() {
        constexpr unsigned op = (HashCode10 & (0b11 << 5)) >> 5 ;
        constexpr std::array<E_DataProcess, 4> opType {MOV, CMP, ADD, SUB} ;

        constexpr uint32_t equivalentArmCode = MakeALUInstruction(
                std::pair(op_filed::Cond(), AL),
                std::pair(op_filed::Imm(), 0x0),
                std::pair(op_filed::OpCode(), opType[op]),
                std::pair(op_filed::S(), true)
        ) ;

        return DataProcessing<equivalentArmCode>();
    }
}

#endif //GGTEST_TYPE3_H

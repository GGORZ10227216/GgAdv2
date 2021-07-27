//
// Created by orzgg on 2021-07-11.
//

#include <arm_encoder_v2.h>

#ifndef GGTEST_TYPE1_H
#define GGTEST_TYPE1_H

namespace gg_core::gg_cpu {
    template <uint32_t HashCode10>
    static constexpr auto ThumbType1() {
        constexpr unsigned op = (HashCode10 & (0b11 << 5)) >> 5 ;
        constexpr std::array<E_ShiftType, 3> shiftType {LSL, LSR, ASR} ;

        constexpr uint32_t equivalentArmCode = MakeALUInstruction(
                std::pair(op_filed::Cond(), AL),
                std::pair(op_filed::Imm(), 0), // 0x0 is ok, just enable I bit
                std::pair(op_filed::OpCode(), MOV),
                std::pair(op_filed::S(), true),
                std::pair(op_filed::ShiftType(), shiftType[op])
        ) ;

        return DataProcessing<equivalentArmCode>();
    }
}

#endif //GGTEST_TYPE1_H

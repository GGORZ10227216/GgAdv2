//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE1_H
#define GGTEST_TYPE1_H

namespace gg_core::gg_cpu {
    template <E_ShiftType ST>
    static void MoveShift(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType1() {
        constexpr unsigned OP = (HashCode10 & (0b11 << 5)) >> 5 ;

        if constexpr (OP == ROR)
            gg_core::Unreachable() ; // ROR is not allow in thumb type1 instruction.

        return &MoveShift<static_cast<E_ShiftType>(OP)>;
    }
}

#endif //GGTEST_TYPE1_H

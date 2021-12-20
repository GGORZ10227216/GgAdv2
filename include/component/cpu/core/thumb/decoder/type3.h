//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE3_H
#define GGTEST_TYPE3_H

namespace gg_core::gg_cpu {
    template <E_DataProcess OP>
    extern void MovCmpAddSub(CPU& instance);

    template <uint32_t HashCode10>
    static constexpr auto ThumbType3() {
        constexpr unsigned OPCODE = (HashCode10 & (0b11 << 5)) >> 5 ;
        constexpr std::array<E_DataProcess, 4> OPLIST = {
                E_DataProcess::MOV, E_DataProcess::CMP, E_DataProcess::ADD, E_DataProcess::SUB
        } ;

        return &MovCmpAddSub<OPLIST[ OPCODE ]>;
    }
}

#endif //GGTEST_TYPE3_H

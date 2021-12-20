//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE5_H
#define GGTEST_TYPE5_H

namespace gg_core::gg_cpu {
    template <auto OP, bool H1, bool H2>
    extern void HiRegOperation_BX(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType5() {
        constexpr auto OPCODE = []() {
            constexpr unsigned op = (HashCode10 & (0b11 << 2)) >> 2 ;
            if constexpr (op == 0b11) {
                return 0 ; // BX
            } // if
            else {
                constexpr std::array<E_DataProcess, 3> LIST = {
                    ADD, CMP, MOV
                } ;

                return LIST[ op ] ;
            } // else
        }();

        constexpr bool H1 = TestBit(HashCode10, 1) ;
        constexpr bool H2 = TestBit(HashCode10, 0) ;

        return &HiRegOperation_BX<OPCODE, H1, H2>;
    }
}

#endif //GGTEST_TYPE5_H

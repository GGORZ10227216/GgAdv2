//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE4_H
#define GGTEST_TYPE4_H

namespace gg_core::gg_cpu {
    template <auto OP>
    static void ALU_Operations(CPU& instance) ;

    template <uint32_t HashCode10>
    static constexpr auto ThumbType4() {
        constexpr unsigned op = HashCode10 & 0b1111 ;

        constexpr auto OPCODE = [&]() {
            switch (op) {
                case 0:
                    return AND ;
                case 1:
                    return EOR;
                case 2: case 3: case 4: case 7: {
                    const auto shType = static_cast<E_ShiftType>(op == 7 ? ROR : op - 2);
                    return shType ;
                }
                case 5 :
                    return ADC ;
                case 6 :
                    return SBC ;
                case 8 :
                    return TST ;
                case 9 :
                    return RSB ;
                case 10 :
                    return CMP ;
                case 11 :
                    return CMN ;
                case 12 :
                    return ORR ;
                case 13 :
                    return 0 ; // MUL
                case 14 :
                    return BIC ;
                case 15 :
                    return MVN ;
            }
        }();

        return &ALU_Operations<OPCODE>;
    }
}

#endif //GGTEST_TYPE4_H

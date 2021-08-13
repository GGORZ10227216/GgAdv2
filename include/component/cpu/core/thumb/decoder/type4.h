//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE4_H
#define GGTEST_TYPE4_H

namespace gg_core::gg_cpu {
    template <auto OP>
    static void ALU_Operations(CPU& instance) ;

    using HandlerType = void(*)(CPU&);

    template <uint32_t HashCode10>
    static constexpr HandlerType ThumbType4() {
        constexpr unsigned op = HashCode10 & 0b1111 ;

        switch (op) {
            case 0:
                return &ALU_Operations<AND> ;
            case 1:
                return &ALU_Operations<EOR>;
            case 2: case 3: case 4: case 7: {
                const auto shType = static_cast<E_ShiftType>(op == 7 ? ROR : op - 2);
                return &ALU_Operations<shType> ;
            }
            case 5 :
                return &ALU_Operations<ADC> ;
            case 6 :
                return &ALU_Operations<SBC> ;
            case 8 :
                return &ALU_Operations<TST> ;
            case 9 :
                return &ALU_Operations<RSB> ;
            case 10 :
                return &ALU_Operations<CMP> ;
            case 11 :
                return &ALU_Operations<CMN> ;
            case 12 :
                return &ALU_Operations<ORR> ;
            case 13 :
                return &ALU_Operations<0>  ; // MUL
            case 14 :
                return &ALU_Operations<BIC>  ;
            case 15 :
                return &ALU_Operations<MVN>  ;
        }

        return nullptr;
    }
}

#endif //GGTEST_TYPE4_H

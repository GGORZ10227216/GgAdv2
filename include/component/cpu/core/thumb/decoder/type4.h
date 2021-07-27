//
// Created by orzgg on 2021-07-11.
//

#include <arm_encoder_v2.h>

#ifndef GGTEST_TYPE4_H
#define GGTEST_TYPE4_H

namespace gg_core::gg_cpu {
    template <uint32_t HashCode10>
    static constexpr auto ThumbType4() {
        constexpr unsigned op = HashCode10 & 0b1111 ;

        constexpr uint32_t equivalentArmCode = [&]() {
            uint32_t result = 0x0 ;

            if constexpr (op == 0b1101) {
                // MUL
            } // if
            else {
                constexpr std::pair<E_DataProcess, E_ShiftType> opcode = [&]() {
                    switch (op) {
                        case 0:
                            return std::pair(AND, LSL) ;
                        case 1:
                            return std::pair(EOR, LSL) ;
                        case 2: case 3: case 4: case 7: {
                            const auto shType = static_cast<E_ShiftType>(op == 7 ? ROR : op - 2);
                            return std::pair(MOV, shType);
                        }
                        case 5 :
                            return std::pair(ADC, LSL) ;
                        case 6 :
                            return std::pair(SBC, LSL) ;
                        case 8 :
                            return std::pair(TST, LSL) ;
                        case 9 :
                            return std::pair(RSB, LSL) ;
                        case 10 :
                            return std::pair(CMP, LSL) ;
                        case 11 :
                            return std::pair(CMN, LSL) ;
                        case 12 :
                            return std::pair(ORR, LSL) ;
                            /*
                            case 13 :
                                return MUL ;
                            */
                        case 14 :
                            return std::pair(BIC, LSL) ;
                        case 15 :
                            return std::pair(MVN, LSL) ;
                    }

                    return std::pair(TEQ, LSL) ;
                }();

                result = MakeALUInstruction(
                        std::pair(op_filed::Cond(), AL),
                        std::pair(op_filed::OpCode(), opcode.first),
                        std::pair(op_filed::Rs(), 0x0), // enable shift by Rs
                        std::pair(op_filed::ShiftType(), opcode.second),
                        std::pair(op_filed::S(), true)
                ) ;
            } // else
        }();

        return DataProcessing<equivalentArmCode>();
    }
}

#endif //GGTEST_TYPE4_H

//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_TYPE4_H
#define GGTEST_TYPE4_H

namespace gg_core::gg_cpu {
template<E_DataProcess OP, SHIFT_BY SHIFT_SRC, E_ShiftType ST>
extern void ALU_Operations(CPU &instance);

static void Multiply_Thumb(CPU &instance);

template<uint32_t HashCode10>
static constexpr auto ThumbType4() {
  constexpr unsigned op = HashCode10 & 0b1111;

  switch (op) {
	case 0:return &ALU_Operations<AND, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 1:return &ALU_Operations<EOR, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 2:return &ALU_Operations<MOV, SHIFT_BY::REG, E_ShiftType::LSL>;
	case 3:return &ALU_Operations<MOV, SHIFT_BY::REG, E_ShiftType::LSR>;
	case 4:return &ALU_Operations<MOV, SHIFT_BY::REG, E_ShiftType::ASR>;
	case 7:return &ALU_Operations<MOV, SHIFT_BY::REG, E_ShiftType::ROR>;
	case 5 :return &ALU_Operations<ADC, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 6 :return &ALU_Operations<SBC, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 8 :return &ALU_Operations<TST, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 9 :return &ALU_Operations<RSB, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 10 :return &ALU_Operations<CMP, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 11 :return &ALU_Operations<CMN, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 12 :return &ALU_Operations<ORR, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 13 :return &Multiply_Thumb; // MUL
	case 14 :return &ALU_Operations<BIC, SHIFT_BY::NONE, E_ShiftType::LSL>;
	case 15 :return &ALU_Operations<MVN, SHIFT_BY::NONE, E_ShiftType::LSL>;
  }
}
}

#endif //GGTEST_TYPE4_H

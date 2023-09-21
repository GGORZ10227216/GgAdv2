//
// Created by orzgg on 2021-07-11.
//

#include <opcode_fields.h>

#ifndef GGTEST_ARM_ENCODER_V2_H
#define GGTEST_ARM_ENCODER_V2_H

namespace gg_core::gg_cpu {
template<typename F, typename V>
constexpr uint32_t ALUInstruction(V value) {
  uint32_t result = 0;
  if constexpr (std::is_same_v < F, op_filed::S >) {
	static_assert(std::is_same_v < V, bool > , "Type missmatch");
	result |= value << 20;
  } // if
  else if constexpr (std::is_same_v < F, op_filed::Cond >) {
	static_assert(std::is_same_v < V, gg_core::gg_cpu::E_CondName > );
	result |= value << 28;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::OpCode >) {
	static_assert(std::is_same_v < V, gg_core::gg_cpu::E_DataProcess > );
	result |= value << 21;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Rn >) {
	static_assert(std::is_integral_v < V > || std::is_same_v < V, gg_core::gg_cpu::E_RegName > );
	result |= value << 16;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Rd >) {
	static_assert(std::is_integral_v < V > || std::is_same_v < V, gg_core::gg_cpu::E_RegName > );
	result |= value << 12;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Rm >) {
	static_assert(std::is_integral_v < V > || std::is_same_v < V, gg_core::gg_cpu::E_RegName > );
	result |= value;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Imm >) {
	result |= (1 << 25) | value;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Rs >) {
	static_assert(std::is_integral_v < V > || std::is_same_v < V, gg_core::gg_cpu::E_RegName > );
	result |= (1 << 4) | (value << 8);
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::Rotate >) {
	static_assert(std::is_integral_v < V > );
	result |= value << 8;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::ShiftType >) {
	static_assert(std::is_integral_v < V > || std::is_same_v < V, gg_core::gg_cpu::E_ShiftType > );
	result |= value << 5;
  } // else if
  else if constexpr (std::is_same_v < F, op_filed::ShiftAmount >) {
	static_assert(std::is_integral_v < V > );
	result |= value << 7;
  } // else if
  else
	gg_core::Unreachable();

  return result;
}

template<typename... Ts>
constexpr uint32_t MakeALUInstruction(Ts... ts) {
  return (ALUInstruction<decltype(ts.first)>(ts.second) | ...);
} // MakeALUInstruction()
}

#endif //GGTEST_ARM_ENCODER_V2_H

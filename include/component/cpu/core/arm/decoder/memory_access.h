//
// Created by buildmachine on 2020-11-30.
//

#include <cstdint>

#include <cpu_enum.h>
#include <bit_manipulate.h>

#ifndef GGTEST_MEMORY_ACCESS_H
#define GGTEST_MEMORY_ACCESS_H

namespace gg_core::gg_cpu {
template<bool I, bool P, bool U, bool B, bool W, bool L, SHIFT_BY SHIFT_SRC, E_ShiftType ST>
static void SingleDataTransfer_impl(CPU &instance);

template<bool P, bool U, bool W, bool L, bool S, bool H, OFFSET_TYPE OT>
static void HalfMemAccess_impl(CPU &instance);

template<bool P, bool U, bool S, bool W, bool L>
static void BlockMemAccess_impl(CPU &instance);

template<bool B>
static void Swap_impl(CPU &instance);

template<uint32_t HashCode32>
static constexpr auto SingleDataTransfer() {
  constexpr SHIFT_BY SHIFT_SRC = TestBit(HashCode32, 4) ? SHIFT_BY::REG : SHIFT_BY::IMM;
  constexpr E_ShiftType ST = static_cast<E_ShiftType>(BitFieldValue<5, 2>(HashCode32));

  return &SingleDataTransfer_impl<
	  TestBit(HashCode32, 25),
	  TestBit(HashCode32, 24),
	  TestBit(HashCode32, 23),
	  TestBit(HashCode32, 22),
	  TestBit(HashCode32, 21),
	  TestBit(HashCode32, 20),
	  SHIFT_SRC,
	  ST
  >;
} // SingleDataTransfer()

template<uint32_t HashCode32>
static constexpr auto HalfDataTransfer() {
  constexpr enum OFFSET_TYPE OT = TestBit(HashCode32, 22) ?
								  OFFSET_TYPE::IMM : OFFSET_TYPE::RM;
  return &HalfMemAccess_impl<
	  TestBit(HashCode32, 24),
	  TestBit(HashCode32, 23),
	  TestBit(HashCode32, 21),
	  TestBit(HashCode32, 20),
	  TestBit(HashCode32, 6),
	  TestBit(HashCode32, 5),
	  OT
  >;
} // HalfDataTransfer()

template<uint32_t HashCode32>
static constexpr auto BlockDataTransfer() {
  return &BlockMemAccess_impl<
	  TestBit(HashCode32, 24),
	  TestBit(HashCode32, 23),
	  TestBit(HashCode32, 22),
	  TestBit(HashCode32, 21),
	  TestBit(HashCode32, 20)
  >;
}

template<uint32_t HashCode32>
static constexpr auto Swap() {
  return &Swap_impl<
	  TestBit(HashCode32, 22)
  >;
} // Swap()
}

#endif //GGTEST_MEMORY_ACCESS_H

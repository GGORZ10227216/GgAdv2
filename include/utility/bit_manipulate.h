//
// Created by orzgg on 2020-09-05.
//

#include <cstdint>
#include <bit>

#ifndef GGADV_BIT_MANIPULATE_H
#define GGADV_BIT_MANIPULATE_H

namespace gg_core {
constexpr uint64_t _BV(uint32_t bitNo) {
  return static_cast<uint64_t>(0x1) << bitNo;
} // _BV()

template<typename T>
constexpr bool TestBit(T bin, uint32_t bitNo) {
  return bin & _BV(bitNo);
} // TestBit()

template<typename T>
inline void SetBit(T &bin, uint32_t bitNo) {
  bin |= _BV(bitNo);
} // SetBit()

template<typename T>
inline void ClearBit(T &bin, uint32_t bitNo) {
  bin &= ~static_cast<T>(_BV(bitNo));
} // ClearBit()

template<unsigned START_BIT, unsigned LENG, typename T>
constexpr auto BitFieldValue(T bin) -> T {
  constexpr T mask = static_cast<T>(~0) >> (sizeof(T) * 8 - LENG);
  return (bin >> START_BIT) & mask;
} // BitFieldValue

template<typename T>
constexpr uint8_t PopCount32(T i) {
  static_assert(sizeof(T) <= 4, "Type size exceed 32 bit");
  i = i - ((i >> 1) & 0x55555555);
  i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
  return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

template<typename T>
constexpr T rotr(T x, uint32_t n) {
#if __cplusplus >= 202002L
  return std::rotr(x, n);
#else
  static_assert(std::is_integral<T>::value, "T is not interral type");
  static_assert(!std::is_signed<T>::value, "T is not unsigned");

  const unsigned int mask = 8*sizeof(n);
  c %= mask;
  return (n>>c) | ((n << (mask - c)));
#endif
}
}

#endif //GGADV_BIT_MANIPULATE_H

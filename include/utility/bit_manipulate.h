//
// Created by orzgg on 2020-09-05.
//

#include <cstdint>

#ifndef GGADV_BIT_MANIPULATE_H
#define GGADV_BIT_MANIPULATE_H

namespace gg_core {
    inline unsigned AddrAlign(uint32_t addr, uint32_t align) {
        return ((addr + align) & ~(align - 1)) - align ;
    } // AddrAlign()

    constexpr uint64_t _BV(uint32_t bitNo) {
        return static_cast<unsigned>(0x1) << bitNo;
    } // _BV()

    template<typename T>
    constexpr bool TestBit(T bin, uint32_t bitNo) {
        return bin & _BV(bitNo);
    } // TestBit()

    template <unsigned START_BIT, unsigned LENG, typename T>
    constexpr auto BitFieldValue(T bin) -> T {
        constexpr T mask = static_cast<T>(~0) >> (sizeof(T)*8 - LENG);
        return (bin >> START_BIT) & mask ;
    } // BitFieldValue

    template <typename T>
    constexpr uint8_t PopCount32(T i) {
        static_assert(sizeof(T) <= 4, "Type's size exceed 32 bit");
        i = i - ((i >> 1) & 0x55555555);
        i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
        return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
    }

    template <typename T>
    constexpr T rotr(T x, uint32_t n) {
        enum {
            CHAR_BIT = 8
        };
        n %= sizeof(T) * CHAR_BIT;
        const size_t shtLeft = CHAR_BIT * sizeof(T) - n;
        if (shtLeft == sizeof(T) * CHAR_BIT)
            return x >> n;
        else
            return x >> n | (x << shtLeft);
    }
}

#endif //GGADV_BIT_MANIPULATE_H

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

    constexpr unsigned _BV(uint32_t bitNo) {
        return 0x1 << bitNo;
    } // _BV()

    template<typename T>
    constexpr bool TestBit(T bin, uint32_t bitNo) {
        return bin & _BV(bitNo);
    } // TestBit()

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

//
// Created by orzgg on 2020-09-04.
//
#include <array>
#include <cstdint>

#include <mem_enum.h>

#ifndef GGADV_DISPLAY_MEMORY_H
#define GGADV_DISPLAY_MEMORY_H

namespace gg_core::gg_mem {
    template <typename W>
    static inline unsigned PALETTE_ACCESS_CYCLE() {
        if constexpr (SameSize<W, DWORD>())
            return 2 ;
        else
            return 1 ;
    }

    template <typename W>
    static inline unsigned VRAM_ACCESS_CYCLE() {
        if constexpr (SameSize<W, DWORD>())
            return 2 ;
        else
            return 1 ;
    }

    static inline unsigned OAM_ACCESS_CYCLE() { return 1 ; }
}

#endif //GGADV_DISPLAY_MEMORY_H

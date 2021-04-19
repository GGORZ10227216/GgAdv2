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

    struct VideoRAM {
        unsigned mode ;

        std::array<uint8_t, 0x400> palette_data;
        std::array<uint8_t, 0x18000> vram_data;
        std::array<uint8_t, 0x400> oam_data;

        const uint32_t BG_Start = 0x0600'0000 ;

        uint32_t BG_End() {
            return (mode <= 2) ? 0x0600'FFFF : 0x0601'3FFF ;
        } // BG_End()

        uint32_t OBJ_Start() {
            return (mode <= 2) ? 0x0601'0000 : 0x0601'4000  ;
        } // OBJ_Start()

        const uint32_t OBJ_End = 0x0601'7FFF ;
    };
}

#endif //GGADV_DISPLAY_MEMORY_H

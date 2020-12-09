//
// Created by orzgg on 2020-09-04.
//
#include <array>
#include <cstdint>

#include <memory_region.h>

#ifndef GGADV_DISPLAY_MEMORY_H
#define GGADV_DISPLAY_MEMORY_H

namespace gg_core::gg_mem {
    struct DisplayMemory : public MemoryRegion<DisplayMemory> {
        DisplayMemory(unsigned& ccRef) : MemoryRegion(ccRef) {

        } // DisplayMemory()

        uint8_t &AccessImpl(unsigned addr, E_AccessWidth width) {
            // todo: cycle counting
            if (addr >= paletteStart && addr <= paletteEnd)
                return palette[addr - paletteStart];
            else if (addr >= VRAM_Start && addr <= VRAM_End) {
                return VRAM[addr - VRAM_Start];
            } // else if()
            else if (addr >= OAM_Start && addr <= OAM_End) {
                return OAM[addr - OAM_Start];
            } // else if

            // fixme: out of bound handler
            return palette[0] ;
        } // Access()

    private :
        std::array<uint8_t, 0x400> palette{};
        std::array<uint8_t, 0x18000> VRAM{};
        std::array<uint8_t, 0x400> OAM{};
    } ;
}

#endif //GGADV_DISPLAY_MEMORY_H

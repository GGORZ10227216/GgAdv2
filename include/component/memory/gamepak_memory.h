//
// Created by orzgg on 2020-09-04.
//

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

#include <memory_region.h>

#ifndef GGADV_GAMEPAK_MEMORY_H
#define GGADV_GAMEPAK_MEMORY_H

namespace gg_core::gg_mem {
    struct GamepakMemory : public MemoryRegion<GamepakMemory> {
        GamepakMemory(const std::optional<std::filesystem::path>& romPath, unsigned& ccRef) :
            MemoryRegion(ccRef)
        {
            SRAM.fill(0) ;
            if (romPath) {
                // todo: load ROM mechanism
            } // if
            else {
                // Boot BIOS only
            } // else
        } // GamepakMemory()

        uint8_t &AccessImpl(unsigned addr, E_AccessWidth width) {
            // todo: cycle counting
            if (addr >= state1Start && addr <= state1End)
                return state1[addr];
            else if (addr >= state2Start && addr <= state2End) {
                return state2[addr - state2Start];
            } // else if()
            else if (addr >= state3Start && addr <= state3End) {
                return state3[addr - state3End];
            } // else if
            else if (addr >= SRAM_Start && addr <= SRAM_End) {
                return SRAM[addr - SRAM_Start];
            } // else if

            // fixme: out of bound handler
            return SRAM[0] ;
        } // Access()

    private :
        // todo: state memory initialize
        std::vector<uint8_t> state1, state2, state3 ;
        std::array<uint8_t, 0x10000> SRAM ;
    } ;
}

#endif //GGADV_GAMEPAK_MEMORY_H

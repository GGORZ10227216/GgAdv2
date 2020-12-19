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
            // todo: open all ROM space(allocated on heap) only for debugging
            state1 = std::make_unique<uint8_t[]>( state1End - state1Start + 1 ) ;
            state2 = std::make_unique<uint8_t[]>( state2End - state2Start + 1 ) ;
            state3 = std::make_unique<uint8_t[]>( state3End - state3Start + 1 ) ;

//            if (romPath) {
//                // todo: load ROM mechanism
//            } // if
//            else {
//                // Boot BIOS only
//            } // else
        } // GamepakMemory()

        uint8_t &AccessImpl(unsigned addr, E_AccessWidth width) {
            // todo: cycle counting
            if (addr >= state1Start && addr <= state1End)
                return state1[addr - state1Start];
            else if (addr >= state2Start && addr <= state2End) {
                return state2[addr - state2Start];
            } // else if()
            else if (addr >= state3Start && addr <= state3End) {
                return state3[addr - state3Start];
            } // else if
            else if (addr >= SRAM_Start && addr <= SRAM_End) {
                return SRAM[addr - SRAM_Start];
            } // else if

            // fixme: out of bound handler
            return SRAM[0] ;
        } // Access()

    private :
        // todo: state memory initialize
        // std::vector<uint8_t> state1, state2, state3 ;
        std::unique_ptr<uint8_t[]> state1, state2, state3 ;
        std::array<uint8_t, 0x10000> SRAM ;
    } ;
}

#endif //GGADV_GAMEPAK_MEMORY_H

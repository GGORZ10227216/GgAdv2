//
// Created by orzgg on 2020-09-04.
//
#include <array>
#include <cstdint>

#include <gba_bios.h>
#include <memory_region.h>

#ifndef GGADV_GENERAL_MEMORY_H
#define GGADV_GENERAL_MEMORY_H

namespace gg_core::gg_mem {
    struct GeneralMemory : public MemoryRegion<GeneralMemory> {
        GeneralMemory(unsigned& ccRef) : MemoryRegion(ccRef) {
            // memcpy( BIOS.data(), biosData.data(), BIOS.size() ) ;
            // fixme: leave bios data to all zero for debugging
            BIOS.fill(0) ;
//            std::array<uint8_t, 36> testProg {
//                    0x12, 0x03, 0x81, 0xe0, 0x32, 0x03, 0x81, 0xe0, 0x52,
//                    0x03, 0x81, 0xe0, 0x72, 0x03, 0x81, 0xe0, 0x02, 0x01,
//                    0x41, 0xe0, 0x22, 0x01, 0x41, 0xe0, 0x42, 0x01, 0x41,
//                    0xe0, 0x62, 0x01, 0x41, 0xe0, 0xf6, 0xff, 0xff, 0xea
//            } ;
//
//            memcpy( BIOS.data(), testProg.data(), testProg.size() ) ;
        } // GeneralMemory()

        uint8_t &AccessImpl(unsigned addr, E_AccessWidth width) {
            // todo: cycle counting
            if (addr <= BIOS_end)
                return BIOS[addr];
            else if (addr >= onboardStart && addr <= onboardEnd) {
                return WRAM_Onboard[addr - onboardStart];
            } // else if()
            else if (addr >= onchipStart && addr <= onchipEnd) {
                return WRAM_Onchip[addr - onchipStart];
            } // else if
            else if (addr >= ioStart && addr <= ioEnd) {
                return IOReg[ addr - ioStart ] ;
            } // else

            // fixme: out of bound handler
            return BIOS[0] ;
        } // Access()
    private :
        std::array<uint8_t, 0x4000> BIOS{};
        std::array<uint8_t, 0x40000> WRAM_Onboard{};
        std::array<uint8_t, 0x8000> WRAM_Onchip{};
        std::array<uint8_t, 0x3ff> IOReg{};
    } ;
}

#endif //GGADV_GENERAL_MEMORY_H

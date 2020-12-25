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
            // todo: memory mirror

            /**
             * Default WRAM Usage
             *     By default, the 256 bytes at 03007F00h-03007FFFh in Work RAM are reserved for
             *     Interrupt vector, Interrupt Stack, and BIOS Call Stack. The remaining WRAM is
             *     free for whatever use (including User Stack, which is initially located at 03007F00h).
             **/

            /**
             * GBA BIOS RAM Usage
             *      Below memory at 3007Fxxh is often accessed directly, or "via mirrors at 3FFFFxxh."
             *      3000000h 7F00h User Memory and User Stack              (sp_usr=3007F00h)
             *      3007F00h A0h   Default Interrupt Stack (6 words/time)  (sp_irq=3007FA0h)
             *      3007FA0h 40h   Default Supervisor Stack (4 words/time) (sp_svc=3007FE0h)
             *      3007FE0h 10h   Debug Exception Stack (4 words/time)    (sp_xxx=3007FF0h)
             *      3007FF0h 4     Pointer to Sound Buffer (for SWI Sound functions)
             *      3007FF4h 3     Reserved (unused)
             *      3007FF7h 1     Reserved (intro/nintendo logo related)
             *      3007FF8h 2     IRQ IF Check Flags (for SWI IntrWait/VBlankIntrWait functions)
             *      3007FFAh 1     Soft Reset Re-entry Flag (for SWI SoftReset function)
             *      3007FFBh 1     Reserved (intro/multiboot slave related)
             *      3007FFCh 4     Pointer to user IRQ handler (to 32bit ARM code)
             **/

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

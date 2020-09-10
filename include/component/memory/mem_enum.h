//
// Created by orzgg on 2020-09-04.
//

#ifndef GGADV_MEM_ENUM_H
#define GGADV_MEM_ENUM_H

namespace gg_core::gg_mem {
    enum E_AccessWidth { BYTE, WORD, DWORD } ;
    // General memroy area
    constexpr static unsigned BIOS_start = 0x0000000, BIOS_end = 0x0003fff;
    constexpr static unsigned onboardStart = 0x2000000, onboardEnd = 0x203ffff;
    constexpr static unsigned onchipStart = 0x3000000, onchipEnd = 0x3007fff;
    constexpr static unsigned ioStart = 0x4000000, ioEnd = 0x40003fe;

    // Video RAM area
    constexpr static unsigned paletteStart = 0x05000000, paletteEnd = 0x050003ff;
    constexpr static unsigned VRAM_Start = 0x06000000, VRAM_End = 0x06017FFF;
    constexpr static unsigned OAM_Start = 0x07000000, OAM_End = 0x070003FF;

    // Gamepak area
    constexpr static unsigned state1Start = 0x08000000, state1End = 0x09FFFFFF;
    constexpr static unsigned state2Start = 0x0A000000, state2End = 0x0BFFFFFF;
    constexpr static unsigned state3Start = 0x0C000000, state3End = 0x0DFFFFFF;
    constexpr static unsigned  SRAM_Start = 0x0E000000, SRAM_End = 0x0E00FFFF;
}

#endif //GGADV_MEM_ENUM_H

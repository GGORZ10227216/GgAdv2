//
// Created by orzgg on 2020-09-04.
//

#ifndef GGADV_MEM_ENUM_H
#define GGADV_MEM_ENUM_H

namespace gg_core::gg_mem {
    using BYTE = uint8_t ;
    using WORD = uint16_t ;
    using DWORD = uint32_t ;

    const unsigned DWORD_SIZE = 4 ;
    const unsigned WORD_SIZE = 2 ;
    const unsigned BYTE_SIZE = 1 ;

    enum E_AccessType { READ, WRITE };
    enum E_GamePakRegion {
        E_WS0, E_WS1, E_WS2, E_SRAM
    } ;

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
    constexpr static unsigned ROM_BLOCK_SIZE = 0x2000000;

    static constexpr std::array<const char *, 2> accessModeName{
            "Read", "Write"
    };

    static constexpr std::array<const char *, 3> accessWidthName{
            "BYTE", "WORD", "DWORD"
    };

    constexpr static std::array<unsigned, 3> N_START_BIT {
            2, 5, 8
    };

    constexpr static std::array<unsigned, 3> S_START_BIT {
            4, 7, 10
    };

    constexpr static std::array<unsigned, 4> N_CYCLE_TABLE {
            4,3,2,8
    };

    constexpr static std::array<unsigned, 6> S_CYCLE_TABLE {
            2, 1, 4, 1, 8, 1
    };
}

#endif //GGADV_MEM_ENUM_H

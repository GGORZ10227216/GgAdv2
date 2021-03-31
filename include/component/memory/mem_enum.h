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

    enum E_BackupMediaType {
        SRAM,
        FLASH
    };

    enum E_ErrorType {
        BIOS_ACCESS_FROM_OUTSIDE,
        ACCESS_INVALID_AREA,
        SRAM_WIDTH_MISMATCH
    };

    // General memroy area
    constexpr static unsigned BIOS_start = 0x0000000, BIOS_end = 0x0003fff;
    constexpr static unsigned onboardStart = 0x2000000, onboardEnd = 0x203ffff;
    constexpr static unsigned onchipStart = 0x3000000, onchipEnd = 0x3007fff;
    constexpr static unsigned ioStart = 0x4000000, ioEnd = 0x40003fe;

    // Video RAM area
    constexpr static unsigned paletteStart = 0x05000000, paletteEnd = 0x050003ff;
    constexpr static unsigned VRAM_Start = 0x06000000, VRAM_End = 0x06017FFF;
    constexpr static unsigned OAM_Start = 0x07000000, OAM_End = 0x070003FF;
    constexpr static unsigned SRAM_Start = 0x0E000000, SRAM_End = 0x0E00FFFF ;

    // Gamepak area
    constexpr static unsigned ROM_BLOCK_SIZE = 0x2000000;

    enum E_RamSize {
        E_BIOS_SIZE = BIOS_end - BIOS_start + 1,
        E_EWRAM_SIZE = onboardEnd - onboardStart + 1,
        E_IWRAM_SIZE = onchipEnd - onchipStart + 1,
        E_IO_SIZE = ioEnd - ioStart + 1,
        E_PALETTE_SIZE = paletteEnd - paletteStart + 1,
        E_VRAM_SIZE = VRAM_End - VRAM_Start + 1,
        E_OAM_SIZE = OAM_End - OAM_Start + 1,
        E_ROM_BLOCK_SIZE = 0x2000000,
        E_SRAM_SIZE = SRAM_End - SRAM_Start + 1
    };

    static constexpr std::array<const char *, 2> accessModeName{
            "Read", "Write"
    };

    static constexpr std::array<const char *, 3> accessWidthName{
            "BYTE", "WORD", "DWORD"
    };

    constexpr static std::array<unsigned, 4> N_CYCLE_TABLE {
            4,3,2,8
    };

    constexpr static std::array<unsigned, 6> S_CYCLE_TABLE {
            2, 1, 4, 1, 8, 1
    };
}

#endif //GGADV_MEM_ENUM_H

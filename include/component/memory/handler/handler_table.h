//
// Created by buildmachine on 2021-03-17.
//

#include <handler/bios_handler.h>
#include <handler/ewram_handler.h>
#include <handler/iwram_handler.h>
#include <handler/io_handler.h>
#include <handler/palette_handler.h>
#include <handler/vram_handler.h>
#include <handler/oam_handler.h>
#include <handler/gamepak_handler.h>
#include <handler/sram_handler.h>

#ifndef GGTEST_HANDLER_TABLE_H
#define GGTEST_HANDLER_TABLE_H

namespace gg_core::gg_mem {
    using ReadHandler = std::tuple<
        uint8_t (*)(MMU_Status*, uint32_t),
        uint16_t(*)(MMU_Status*, uint32_t),
        uint32_t(*)(MMU_Status*, uint32_t)
    >;

    using WriteHandler = std::tuple<
        void(*)(MMU_Status*, uint32_t, uint8_t),
        void(*)(MMU_Status*, uint32_t, uint16_t),
        void(*)(MMU_Status*, uint32_t, uint32_t)
    >;

    constexpr static std::array<ReadHandler, 16> ReadHandlers {
        /*0x0 BIOS*/      ReadHandler(BIOS_Read<uint8_t>, BIOS_Read<uint16_t>, BIOS_Read<uint32_t>),
        /*0x1 NO USED*/   ReadHandler(NoUsed_Read<uint8_t>, NoUsed_Read<uint16_t>, NoUsed_Read<uint32_t>),
        /*0x2 EWRAM*/     ReadHandler(EWRAM_Read<uint8_t>, EWRAM_Read<uint16_t>, EWRAM_Read<uint32_t>),
        /*0x3 IWRAM*/     ReadHandler(IWRAM_Read<uint8_t>, IWRAM_Read<uint16_t>, IWRAM_Read<uint32_t>),
        /*0x4 IO*/        ReadHandler(IO_Read<uint8_t>, IO_Read<uint16_t>, IO_Read<uint32_t>),
        /*0x5 Palette*/   ReadHandler(Palette_Read<uint8_t>, Palette_Read<uint16_t>, Palette_Read<uint32_t>),
        /*0x6 VRAM*/      ReadHandler(VRAM_Read<uint8_t>, VRAM_Read<uint16_t>, VRAM_Read<uint32_t>),
        /*0x7 OAM*/       ReadHandler(OAM_Read<uint8_t>, OAM_Read<uint16_t>, OAM_Read<uint32_t>),
        /*0x8 GAMEPAK_0*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS0>, GAMEPAK_Read<uint16_t, E_WS0>, GAMEPAK_Read<uint32_t, E_WS0>),
        /*0x9 GAMEPAK_0*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS0>, GAMEPAK_Read<uint16_t, E_WS0>, GAMEPAK_Read<uint32_t, E_WS0>),
        /*0xA GAMEPAK_1*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS1>, GAMEPAK_Read<uint16_t, E_WS1>, GAMEPAK_Read<uint32_t, E_WS1>),
        /*0xB GAMEPAK_1*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS1>, GAMEPAK_Read<uint16_t, E_WS1>, GAMEPAK_Read<uint32_t, E_WS1>),
        /*0xC GAMEPAK_2*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS2>, GAMEPAK_Read<uint16_t, E_WS2>, GAMEPAK_Read<uint32_t, E_WS2>),
        /*0xD GAMEPAK_2*/ ReadHandler(GAMEPAK_Read<uint8_t, E_WS2>, GAMEPAK_Read<uint16_t, E_WS2>, GAMEPAK_Read<uint32_t, E_WS2>),
        /*0xE SRAM*/      ReadHandler(GAMEPAK_Read<uint8_t, E_SRAM>, GAMEPAK_Read<uint16_t, E_SRAM>, GAMEPAK_Read<uint32_t, E_SRAM>),
        /*0xF SRAM_MIRROR*/ReadHandler(GAMEPAK_Read<uint8_t, E_SRAM>, GAMEPAK_Read<uint16_t, E_SRAM>, GAMEPAK_Read<uint32_t, E_SRAM>)
    };

    constexpr static std::array<WriteHandler, 16> WriteHandlers {
        /*0x0 BIOS*/      WriteHandler(BIOS_Write<uint8_t>, BIOS_Write<uint16_t>, BIOS_Write<uint32_t>),
        /*0x1 NO USED*/   WriteHandler(NoUsed_Write<uint8_t>, NoUsed_Write<uint16_t>, NoUsed_Write<uint32_t>),
        /*0x2 EWRAM*/     WriteHandler(EWRAM_Write<uint8_t>, EWRAM_Write<uint16_t>, EWRAM_Write<uint32_t>),
        /*0x3 IWRAM*/     WriteHandler(IWRAM_Write<uint8_t>, IWRAM_Write<uint16_t>, IWRAM_Write<uint32_t>),
        /*0x4 IO*/        WriteHandler(IO_Write<uint8_t>, IO_Write<uint16_t>, IO_Write<uint32_t>),
        /*0x5 Palette*/   WriteHandler(Palette_Write<uint8_t>, Palette_Write<uint16_t>, Palette_Write<uint32_t>),
        /*0x6 VRAM*/      WriteHandler(VRAM_Write<uint8_t>, VRAM_Write<uint16_t>, VRAM_Write<uint32_t>),
        /*0x7 OAM*/       WriteHandler(OAM_Write<uint8_t>, OAM_Write<uint16_t>, OAM_Write<uint32_t>),
        /*0x8 GAMEPAK_0*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS0>, GAMEPAK_Write<uint16_t, E_WS0>, GAMEPAK_Write<uint32_t, E_WS0>),
        /*0x9 GAMEPAK_0*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS0>, GAMEPAK_Write<uint16_t, E_WS0>, GAMEPAK_Write<uint32_t, E_WS0>),
        /*0xA GAMEPAK_1*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS1>, GAMEPAK_Write<uint16_t, E_WS1>, GAMEPAK_Write<uint32_t, E_WS1>),
        /*0xB GAMEPAK_1*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS1>, GAMEPAK_Write<uint16_t, E_WS1>, GAMEPAK_Write<uint32_t, E_WS1>),
        /*0xC GAMEPAK_2*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS2>, GAMEPAK_Write<uint16_t, E_WS2>, GAMEPAK_Write<uint32_t, E_WS2>),
        /*0xD GAMEPAK_2*/ WriteHandler(GAMEPAK_Write<uint8_t, E_WS2>, GAMEPAK_Write<uint16_t, E_WS2>, GAMEPAK_Write<uint32_t, E_WS2>),
        /*0xE SRAM*/      WriteHandler(GAMEPAK_Write<uint8_t, E_SRAM>, GAMEPAK_Write<uint16_t, E_SRAM>, GAMEPAK_Write<uint32_t, E_SRAM>),
        /*0xF SRAM_MIRROR*/WriteHandler(GAMEPAK_Write<uint8_t, E_SRAM>, GAMEPAK_Write<uint16_t, E_SRAM>, GAMEPAK_Write<uint32_t, E_SRAM>)
    };
}

#endif //GGTEST_HANDLER_TABLE_H

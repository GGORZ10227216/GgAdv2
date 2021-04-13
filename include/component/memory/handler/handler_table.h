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
    using AccessHandler = std::tuple<
        uint8_t (*)(MMU_Status*, uint32_t),
        uint16_t(*)(MMU_Status*, uint32_t),
        uint32_t(*)(MMU_Status*, uint32_t)
    >;

    // todo: finish the table
    constexpr static std::array<AccessHandler, 16> ReadHandlers {
        /*0x0 BIOS*/      AccessHandler(BIOS_Read<uint8_t>, BIOS_Read<uint16_t>, BIOS_Read<uint32_t>),
        /*0x1 NO USED*/   AccessHandler(NoUsed_Read<uint8_t>, NoUsed_Read<uint16_t>, NoUsed_Read<uint32_t>),
        /*0x2 EWRAM*/     AccessHandler(EWRAM_Read<uint8_t>, EWRAM_Read<uint16_t>, EWRAM_Read<uint32_t>),
        /*0x3 IWRAM*/     AccessHandler(IWRAM_Read<uint8_t>, IWRAM_Read<uint16_t>, IWRAM_Read<uint32_t>),
        /*0x4 IO*/        AccessHandler(IO_Read<uint8_t>, IO_Read<uint16_t>, IO_Read<uint32_t>),
        /*0x5 Palette*/   AccessHandler(Palette_Read<uint8_t>, Palette_Read<uint16_t>, Palette_Read<uint32_t>),
        /*0x6 VRAM*/      AccessHandler(VRAM_Read<uint8_t>, VRAM_Read<uint16_t>, VRAM_Read<uint32_t>),
        /*0x7 OAM*/       AccessHandler(OAM_Read<uint8_t>, OAM_Read<uint16_t>, OAM_Read<uint32_t>),
        /*0x8 GAMEPAK_0*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS0>, GAMEPAK_Read<uint16_t, E_WS0>, GAMEPAK_Read<uint32_t, E_WS0>),
        /*0x9 GAMEPAK_0*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS0>, GAMEPAK_Read<uint16_t, E_WS0>, GAMEPAK_Read<uint32_t, E_WS0>),
        /*0xA GAMEPAK_1*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS1>, GAMEPAK_Read<uint16_t, E_WS1>, GAMEPAK_Read<uint32_t, E_WS1>),
        /*0xB GAMEPAK_1*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS1>, GAMEPAK_Read<uint16_t, E_WS1>, GAMEPAK_Read<uint32_t, E_WS1>),
        /*0xC GAMEPAK_2*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS2>, GAMEPAK_Read<uint16_t, E_WS2>, GAMEPAK_Read<uint32_t, E_WS2>),
        /*0xD GAMEPAK_2*/ AccessHandler(GAMEPAK_Read<uint8_t, E_WS2>, GAMEPAK_Read<uint16_t, E_WS2>, GAMEPAK_Read<uint32_t, E_WS2>),
        /*0xE SRAM*/      AccessHandler(GAMEPAK_Read<uint8_t, E_SRAM>, GAMEPAK_Read<uint16_t, E_SRAM>, GAMEPAK_Read<uint32_t, E_SRAM>),
        /*0xF NO USED*/   AccessHandler(NoUsed_Read<uint8_t>, NoUsed_Read<uint16_t>, NoUsed_Read<uint32_t>)
    };
}

#endif //GGTEST_HANDLER_TABLE_H

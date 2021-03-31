//
// Created by buildmachine on 2021-03-18.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_GAMEPAK_HANDLER_H
#define GGTEST_GAMEPAK_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T, E_GamePakRegion P>
    T ROM_Read(MMU_Status* mmu, uint32_t addr) {
        uint32_t relativeAddr = addr ;

        if constexpr (P == E_WS0)
            relativeAddr -= 0x0800'0000 ;
        else if constexpr (P == E_WS1)
            relativeAddr -= 0x0A00'0000 ;
        else if constexpr (P == E_WS2) {
            relativeAddr -= 0x0C00'0000 ;
            if (mmu->cartridge.SaveType() == E_EEPROM && mmu->cartridge.IsEEPROM_Access(addr)) {

            } // if
        } // if
        else
            gg_core::Unreachable() ;

        mmu->_cycleCounter =  GAMEPAK_ACCESS_CYCLE<T, P>();
        return reinterpret_cast<T&>(mmu->cartridge[relativeAddr]) ;
    }

    template <typename T, E_GamePakRegion P>
    T ROM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        GGLOG(
            fmt::format("Attempt to write {} value {} to ROM{}(0x{:x})",
                accessWidthName[sizeof(T) >> 1],
                data,
                static_cast<int>(P),
                addr
            )
        );
        return ;
    }
}

#endif //GGTEST_GAMEPAK_HANDLER_H

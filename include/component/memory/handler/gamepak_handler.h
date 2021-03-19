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
    T GamePak_Read(MMU_Status* mmu, uint32_t addr) {
        uint32_t relativeAddr = 0x0800'0000 ;
        std::vector<uint8_t>& bank = mmu->ROM_WS0 ;
        if constexpr (P == E_WS1) {
            relativeAddr = 0x0900'0000;
            bank = mmu->ROM_WS1;
        } // if
        else if constexpr (P == E_WS2) {
            relativeAddr = 0x0C00'0000;
            bank = mmu->ROM_WS2 ;
        } // else if
        else
            Unreachable() ;

        mmu->_cycleCounter =  GAMEPAK_ACCESS_CYCLE<T, P>();
        return reinterpret_cast<T&>(bank[relativeAddr]) ;
    }

    template <typename T, E_GamePakRegion P>
    T GamePak_Write(MMU_Status* mmu, uint32_t addr, T data) {
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

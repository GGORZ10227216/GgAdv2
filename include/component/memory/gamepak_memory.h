//
// Created by orzgg on 2020-09-04.
//

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

#include <mem_enum.h>

#ifndef GGADV_GAMEPAK_MEMORY_H
#define GGADV_GAMEPAK_MEMORY_H

namespace gg_core::gg_mem {
    template<typename W, E_GamePakRegion R>
    inline unsigned GAMEPAK_ACCESS_CYCLE(MMU_Status* mmu, uint32_t addr) {
        if (mmu->requestAccessType == I_Cycle) {
            return 1; // It's an I_Cycle cycle, count it for CPU
        } // if
        else {
            const uint8_t &N_WaitState = mmu->CurrentWaitStates[R].first;
            const uint8_t &S_WaitState = mmu->CurrentWaitStates[R].second;

            unsigned firstAccessCycle = mmu->requestAccessType == gg_mem::S_Cycle ? S_WaitState : N_WaitState ;

            if constexpr (SameSize<W, DWORD>())
                return (1 + firstAccessCycle) + (1 + S_WaitState);
            else
                return (1 + firstAccessCycle);
        } // else
    } // ROM_ACCESS_CYCLE()
}

#endif //GGADV_GAMEPAK_MEMORY_H

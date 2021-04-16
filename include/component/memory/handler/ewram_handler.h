//
// Created by buildmachine on 2021-03-16.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <handler/mirror.h>
#include <gg_utility.h>

#ifndef GGTEST_EWRAM_HANDLER_H
#define GGTEST_EWRAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto EWRAM_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_EWRAM_SIZE);
        mmu->_cycleCounter += EWRAM_ACCESS_CYCLE<T>();
        return reinterpret_cast<T&>(mmu->EWRAM[ relativeAddr ]);
    } // EWRAM_Read()

    template <typename T>
    void EWRAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_EWRAM_SIZE);
        mmu->_cycleCounter += EWRAM_ACCESS_CYCLE<T>();
        reinterpret_cast<T&>(mmu->EWRAM[ relativeAddr ]) = data;
    } // EWRAM_Write()
}

#endif //GGTEST_EWRAM_HANDLER_H

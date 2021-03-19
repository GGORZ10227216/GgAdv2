//
// Created by buildmachine on 2021-03-17.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_PALETTE_HANDLER_H
#define GGTEST_PALETTE_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto Palette_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_PALETTE_SIZE);
        mmu->_cycleCounter = PALETTE_ACCESS_CYCLE<T>();
        return *reinterpret_cast<T*>(mmu->palette.data() + relativeAddr);
    } // IWRAM_Read()

    template <typename T>
    void Palette_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_PALETTE_SIZE);
        mmu->_cycleCounter = PALETTE_ACCESS_CYCLE<T>();
        *reinterpret_cast<T*>(mmu->palette.data() + relativeAddr) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_PALETTE_HANDLER_H

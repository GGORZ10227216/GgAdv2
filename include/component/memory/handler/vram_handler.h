//
// Created by buildmachine on 2021-03-17.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_VRAM_HANDLER_H
#define GGTEST_VRAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto VRAM_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = VRAM_MIRROR(addr);
        mmu->_cycleCounter = VRAM_ACCESS_CYCLE<T>();
        return *reinterpret_cast<T*>(mmu->VRAM.data() + relativeAddr);
    } // IWRAM_Read()

    template <typename T>
    void VRAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = VRAM_MIRROR(addr);
        mmu->_cycleCounter = VRAM_ACCESS_CYCLE<T>();
        *reinterpret_cast<T*>(mmu->VRAM.data() + relativeAddr) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_VRAM_HANDLER_H

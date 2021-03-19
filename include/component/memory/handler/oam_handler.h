//
// Created by buildmachine on 2021-03-17.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_OAM_HANDLER_H
#define GGTEST_OAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto OAM_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_OAM_SIZE);
        mmu->_cycleCounter = OAM_ACCESS_CYCLE();
        return reinterpret_cast<T&>(mmu->OAM[relativeAddr]);
    } // IWRAM_Read()

    template <typename T>
    void OAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_OAM_SIZE);
        mmu->_cycleCounter = OAM_ACCESS_CYCLE();
        reinterpret_cast<T&>(mmu->OAM[relativeAddr]) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_OAM_HANDLER_H

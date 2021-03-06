//
// Created by buildmachine on 2021-03-16.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <handler/mirror.h>
#include <gg_utility.h>

#ifndef GGTEST_IWRAM_HANDLER_H
#define GGTEST_IWRAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto IWRAM_Read(MMU_Status* mmu, uint32_t absAddr) {
        const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_IWRAM_SIZE);
        mmu->_cycleCounter += IWRAM_ACCESS_CYCLE();
        return reinterpret_cast<T&>(mmu->IWRAM[ relativeAddr ]);
    } // IWRAM_Read()

    template <typename T>
    void IWRAM_Write(MMU_Status* mmu, uint32_t absAddr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_IWRAM_SIZE);
        mmu->_cycleCounter += IWRAM_ACCESS_CYCLE();
        reinterpret_cast<T&>(mmu->IWRAM[ relativeAddr ]) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_IWRAM_HANDLER_H

//
// Created by buildmachine on 2021-03-16.
//


#include <mem_enum.h>
#include <handler/mirror.h>
#include <gg_utility.h>

#ifndef GGTEST_EWRAM_HANDLER_H
#define GGTEST_EWRAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    auto EWRAM_Read(GbaInstance& instance, uint32_t absAddr) {
        const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_EWRAM_SIZE);
        return reinterpret_cast<T&>(instance.mmu.EWRAM[ relativeAddr ]);
    } // EWRAM_Read()

    template <typename T>
    void EWRAM_Write(GbaInstance& instance, uint32_t absAddr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_EWRAM_SIZE);
        reinterpret_cast<T&>(instance.mmu.EWRAM[ relativeAddr ]) = data;
    } // EWRAM_Write()
}

#endif //GGTEST_EWRAM_HANDLER_H

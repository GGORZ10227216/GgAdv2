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
        VideoRAM& vram = mmu->VideoRAM ;
        mmu->_cycleCounter += PALETTE_ACCESS_CYCLE<T>();
        return reinterpret_cast<T&>(vram.palette_data[ relativeAddr ]);
    } // IWRAM_Read()

    template <typename T>
    void Palette_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = NORMAL_MIRROR(addr, E_PALETTE_SIZE);
        VideoRAM& vram = mmu->VideoRAM ;
        mmu->_cycleCounter += PALETTE_ACCESS_CYCLE<T>();

        if constexpr (sizeof(T) == 1) {
            // byte write to palette memory is undefined behavior,
            // but we can emulate it by logic below:
            // [addr_align_by_16] = data * 0x101
            const uint32_t addrRealign = relativeAddr & (~0x1) ;
            uint16_t newData = data ;
            newData = (newData << 8) | data ;
            reinterpret_cast<T&>(vram.palette_data[ addrRealign ]) = newData;
            return ;
        } // if

        reinterpret_cast<T&>(vram.palette_data[ relativeAddr ]) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_PALETTE_HANDLER_H

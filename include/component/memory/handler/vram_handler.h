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
        VideoRAM& vram = mmu->VideoRAM ;
        mmu->_cycleCounter += VRAM_ACCESS_CYCLE<T>();
        return reinterpret_cast<T&>(vram.vram_data[relativeAddr]);
    } // IWRAM_Read()

    template <typename T>
    void VRAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = VRAM_MIRROR(addr);
        VideoRAM& vram = mmu->VideoRAM ;
        mmu->_cycleCounter += VRAM_ACCESS_CYCLE<T>();

        if constexpr (sizeof(T) == 1) {
            // byte write to palette VRAM is undefined behavior,
            // but the behavior of OBJ and BG are different
            // we can emulate it by logic below:
            //     BG: [addr_align_by_16] = data * 0x101
            //     OBJ: just ignore
            if (addr >= mmu->VideoRAM.BG_Start && addr <= mmu->VideoRAM.BG_End()) {
                const uint32_t addrRealign = relativeAddr & (~0x1) ;
                uint16_t newData = data ;
                newData = (newData << 8) | data ;
                reinterpret_cast<T&>(vram.vram_data[ addrRealign ]) = newData;
                return ;
            } // if
            else
                return ;
        } // if constexpr

        reinterpret_cast<T&>(vram.vram_data[ relativeAddr ]) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_VRAM_HANDLER_H

//
// Created by buildmachine on 2021-03-17.
//

#ifndef GGTEST_MIRROR_H
#define GGTEST_MIRROR_H

namespace gg_core::gg_mem {
    inline uint32_t NORMAL_MIRROR(uint32_t addr, uint32_t regionSize) {
        return addr & (regionSize - 1) ;
    }

    inline uint32_t VRAM_MIRROR(uint32_t addr) {
        return addr & ((addr & 0x10000) ? 0x17fff : 0x0'ffff);
    }

    template <E_BackupMediaType T>
    inline uint32_t SRAM_MIRROR(MMU_Status* mmu, uint32_t addr) {
        if (T == SRAM)
            return addr & 0x7fff;
        else
            return addr & 0xffff;
    }
}

#endif //GGTEST_MIRROR_H

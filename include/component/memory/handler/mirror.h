//
// Created by buildmachine on 2021-03-17.
//

#ifndef GGTEST_MIRROR_H
#define GGTEST_MIRROR_H

namespace gg_core::gg_mem {
    inline uint32_t NORMAL_MIRROR(uint32_t absAddr, uint32_t regionSize) {
        return absAddr & (regionSize - 1) ;
    }

    inline uint32_t VRAM_MIRROR(uint32_t absAddr) {
        return absAddr & ((absAddr & 0x10000) ? 0x17fff : 0x0'ffff);
    }

    inline uint32_t SRAM_MIRROR(MMU_Status* mmu, uint32_t absAddr) {
        return absAddr & mmu->cartridge.GetSRAM_MirrorMask();
    }
}

#endif //GGTEST_MIRROR_H

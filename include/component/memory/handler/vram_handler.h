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
    auto VRAM_Read(MMU_Status* mmu, uint32_t absAddr) {
        const uint32_t relativeAddr = VRAM_MIRROR(AlignAddr<T>(absAddr));
        VideoRAM& vram = mmu->videoRAM ;
        mmu->_cycleCounter += VRAM_ACCESS_CYCLE<T>();
        return reinterpret_cast<T&>(vram.vram_data[relativeAddr]);
    } // IWRAM_Read()

    template <typename T>
    void VRAM_Write(MMU_Status* mmu, uint32_t absAddr, T data) {
        const uint32_t relativeAddr = VRAM_MIRROR(AlignAddr<T>(absAddr));
        VideoRAM& vram = mmu->videoRAM ;
        mmu->_cycleCounter += VRAM_ACCESS_CYCLE<T>();

        if constexpr (sizeof(T) == 1) {
            // byte write to palette VRAM is undefined behavior,
            // but the behavior of OBJ and BG are different
            // we can emulate it by logic below:
            //     BG: [addr_align_by_16] = data * 0x101
            //     OBJ: just ignore
            absAddr = gg_mem::VRAM_Start + relativeAddr ;
            if (absAddr >= mmu->videoRAM.BG_Start && absAddr <= mmu->videoRAM.BG_End()) {
                const uint32_t addrRealign = relativeAddr & (~0x1) ;
                reinterpret_cast<uint16_t&>(vram.vram_data[ addrRealign ]) = data*0x101;
                return ;
            } // if
            else {
                // Write to OBJ 0x06010000-0x06017fff(or 6014000h-6017FFFh in Bitmap mode)
                // are ignored.
                return ;
            } // else
        } // if constexpr

        reinterpret_cast<T&>(vram.vram_data[ relativeAddr ]) = data;
    } // IWRAM_Write()
}

#endif //GGTEST_VRAM_HANDLER_H

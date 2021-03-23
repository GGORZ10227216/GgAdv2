//
// Created by buildmachine on 2021-03-18.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_SRAM_HANDLER_H
#define GGTEST_SRAM_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    T SRAM_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = SRAM_MIRROR(mmu, addr);

        // SRAM is only allow byte access
        mmu->_cycleCounter = GAMEPAK_ACCESS_CYCLE<uint8_t, E_SRAM>(mmu);
        if constexpr (sizeof(T) == 1)
            return mmu->cartridge.SRAM[ relativeAddr ] ;
        else  {
            GGLOG(fmt::format(
                    "Attempt to READ {} value from SRAM 0x{:x}",
                    accessWidthName[ sizeof(T) >> 1 ],
                    addr
            ).c_str());

            return static_cast<T>(mmu->cartridge.SRAM[ relativeAddr ]) * static_cast<T>(0x01010101) ;
        } // else
    } // SRAM_Read()

    template <typename T>
    void SRAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = SRAM_MIRROR(mmu,addr);
        mmu->_cycleCounter = OAM_ACCESS_CYCLE();
        reinterpret_cast<T&>(mmu->OAM[relativeAddr]) = data;
    }
}

#endif //GGTEST_SRAM_HANDLER_H

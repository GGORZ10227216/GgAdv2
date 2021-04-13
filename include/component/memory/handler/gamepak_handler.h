//
// Created by buildmachine on 2021-03-18.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_GAMEPAK_HANDLER_H
#define GGTEST_GAMEPAK_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    T SRAM_Read(MMU_Status* mmu, uint32_t absAddr) {
        const uint32_t relativeAddr = SRAM_MIRROR(mmu, absAddr);
        mmu->_cycleCounter += GAMEPAK_ACCESS_CYCLE<uint8_t, E_SRAM>(mmu);

        // SRAM is only allow byte access
        if constexpr (sizeof(T) == 1)
            return mmu->cartridge.SRAM[ relativeAddr ] ;
        else  {
            GGLOG(fmt::format(
                    "Attempt to READ {} value from SRAM 0x{:x}",
                    accessWidthName[ sizeof(T) >> 1 ],
                    absAddr
            ).c_str());

            return static_cast<T>(mmu->cartridge.SRAM[ relativeAddr ]) * static_cast<T>(0x01010101) ;
        } // else
    } // SRAM_Read()

    template <typename T, E_GamePakRegion P>
    T GAMEPAK_Read(MMU_Status* mmu, uint32_t absAddr) {
        Cartridge& cart = mmu->cartridge ;
        uint32_t relativeAddr = cart.RelativeAddr<P>(absAddr) ;

        mmu->_cycleCounter +=  GAMEPAK_ACCESS_CYCLE<T, P>(mmu);
        if constexpr (P == E_WS2) {
            // If absAddr is in EEPROM region and cart has a EEPROM attached, 
            // that means this access is a EEPROM access.
            // Otherwise, go through normal GamePak access logic below.
            if (cart.IsEEPROM_Access(absAddr) && cart.SaveType() == E_EEPROM)
                return cart.eeprom.ReadData() ;
        } // if
        else if constexpr (P == E_SRAM) {
            // Whole 0x0EXX'XXXX region are belong to SRAM, so this is 
            // impossible a normal ROM access if P == E_SRAM.
            // eg. this constexpr if will always return first.
            return SRAM_Read<T>(mmu, absAddr) ;
        } // else if
        
        // normal ROM access logic begin here
        return reinterpret_cast<T&>(cart.romData[relativeAddr]) ;
    } // ROM_Read()

    template <typename T>
    void SRAM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        const uint32_t relativeAddr = SRAM_MIRROR(mmu,addr);
        mmu->_cycleCounter += GAMEPAK_ACCESS_CYCLE<uint8_t, E_SRAM>(mmu);
        reinterpret_cast<T&>(mmu->cartridge.SRAM[relativeAddr]) = data;
    }

    template <typename T, E_GamePakRegion P>
    T ROM_Write(MMU_Status* mmu, uint32_t addr, T data) {
        // todo: DMA3 implement
        GGLOG(
            fmt::format("Attempt to write {} value {} to ROM{}(0x{:x})",
                accessWidthName[sizeof(T) >> 1],
                data,
                static_cast<int>(P),
                addr
            )
        );

        return ;
    }
}

#endif //GGTEST_GAMEPAK_HANDLER_H

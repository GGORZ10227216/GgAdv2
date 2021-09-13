//
// Created by buildmachine on 2021-03-16.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_BIOS_HANDLER_H
#define GGTEST_BIOS_HANDLER_H

namespace gg_core::gg_mem {
    template<typename T>
    T BIOS_Read(MMU_Status *mmu, uint32_t absAddr) {
        const uint32_t targetAddr = AlignAddr<T>(absAddr);

        if (targetAddr < E_RamSize::E_BIOS_SIZE) {
            mmu->_cycleCounter += BIOS_ACCESS_CYCLE();
            if (mmu->_cpuStatus->_regs[gg_cpu::pc] <= 0x3fff) {
                mmu->bios_readBuf = reinterpret_cast<uint32_t&>(mmu->bios_data[targetAddr]);
                return reinterpret_cast<T&>(mmu->bios_data[targetAddr]);
            } // if
            else
                return static_cast<T>(mmu->bios_readBuf);
        } // if
        else
            return static_cast<T>(mmu->IllegalReadValue());
    } // BIOS_Read()

    template<typename T>
    void BIOS_Write(MMU_Status *mmu, uint32_t absAddr, T data) {
        mmu->logger->warn(
                "Attempt to WRITE {} value ({}) to BIOS area({})",
                accessWidthName[sizeof(T) >> 1],
                data,
                absAddr
        );
    }

    template<typename T>
    T NoUsed_Read(MMU_Status *mmu, uint32_t absAddr) {
        unsigned memoryBusMask = 0x0 ;
        if constexpr (sizeof(T) == 1)
            memoryBusMask = 0b11 ;
        else if constexpr (sizeof(T) == 2)
            memoryBusMask = 0b10 ;

        mmu->logger->warn(
                "Attempt to READ {} from address 0x{:x}",
                accessWidthName[sizeof(T) >> 1],
                absAddr
        );

        return (mmu->IllegalReadValue() >> ((absAddr & memoryBusMask) << 3)) & static_cast<T>(0xffffffff);
    } // NoUsed_Read()

    template<typename T>
    void NoUsed_Write(MMU_Status *mmu, uint32_t absAddr, T data) {
        mmu->logger->warn(
                "Attempt to WRITE {} value (0x{:x}) to unused area(0x{:x})",
                accessWidthName[sizeof(T) >> 1],
                data,
                absAddr
        );
    } // NoUsed_Write()
}

#endif //GGTEST_BIOS_HANDLER_H

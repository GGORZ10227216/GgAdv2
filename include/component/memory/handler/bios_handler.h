//
// Created by buildmachine on 2021-03-16.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_BIOS_HANDLER_H
#define GGTEST_BIOS_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    T IllegalShift(uint32_t value, uint32_t absAddr) {
        // Just found that mgba has this wired behavior, not sure NO$GBA's.....
        const unsigned memoryBusMask = sizeof(uint32_t) - sizeof(T) ;
        return (value >> ((absAddr & memoryBusMask) << 3)) & static_cast<T>(0xffffffff);
    } // IllegalShift()

    template<typename T>
    T NoUsed_Read(MMU_Status *mmu, uint32_t absAddr) {
        mmu->logger->warn(
                "Attempt to READ {} from address 0x{:x}",
                accessWidthName[sizeof(T) >> 1],
                absAddr
        );

        return IllegalShift<T>(mmu->IllegalReadValue(), absAddr);
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

    template<typename T>
    T BIOS_Read(MMU_Status *mmu, uint32_t absAddr) {
        const uint32_t targetAddr = AlignAddr<T>(absAddr);

        if (targetAddr < E_RamSize::E_BIOS_SIZE) {
            if (mmu->_cpuStatus->_regs[gg_cpu::pc] <= 0x3fff) {
                if constexpr (sizeof(T) == sizeof(uint32_t))
                    mmu->bios_readBuf = reinterpret_cast<uint32_t&>(mmu->bios_data[targetAddr]); // only fetched opcode will affect read buffer
                return reinterpret_cast<T&>(mmu->bios_data[targetAddr]);
            } // if
            else
                return IllegalShift<T>(mmu->bios_readBuf, absAddr);
        } // if
        else
            return NoUsed_Read<T>(mmu, absAddr);
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
}

#endif //GGTEST_BIOS_HANDLER_H

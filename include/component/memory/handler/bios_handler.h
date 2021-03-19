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
    T BIOS_Read(MMU_Status* mmu, uint32_t addr) {
        const uint32_t relativeAddr = addr ;

        if (relativeAddr < E_RamSize::E_BIOS_SIZE) {
            mmu->_cycleCounter = BIOS_ACCESS_CYCLE();
            if (mmu->_cpuStatus->_regs[gg_cpu::pc] <= 0x3fff) {
                mmu->bios_readBuf = mmu->bios_data[relativeAddr];
                return *reinterpret_cast<T*>(mmu->bios_data.data() + relativeAddr);
            } // if
            else
                return static_cast<T>(mmu->bios_readBuf) ;
        } // if
        else
            return static_cast<T>(mmu->IllegalReadValue()) ;
    } // BIOS_Read()

    template <typename T>
    void BIOS_Write(MMU_Status* mmu, uint32_t addr, T data) {
        gg_core::GGLOG(fmt::format(
                "Attempt to WRITE {} value ({}) to BIOS area({})",
                accessWidthName[ sizeof(T) >> 1 ],
                data,
                addr
            ).c_str()
        );
    }

    template <typename T>
    T NoUsed_Read(MMU_Status* mmu, uint32_t addr) {
        gg_core::GGLOG(fmt::format(
            "Attempt to READ {} from address 0x{:x}",
            accessWidthName[ sizeof(T) >> 1 ],
            addr
        ).c_str());

        return mmu->IllegalReadValue() ;
    } // BIOS_Read()

    template <typename T>
    void NoUsed_Write(MMU_Status* mmu, uint32_t addr, T data) {
        gg_core::GGLOG(fmt::format(
                "Attempt to WRITE {} value ({}) to unused area({})",
                accessWidthName[ sizeof(T) >> 1 ],
                data,
                addr
            ).c_str()
        );
    }
}

#endif //GGTEST_BIOS_HANDLER_H

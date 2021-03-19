//
// Created by buildmachine on 2021-03-16.
//

#include <mmu_status.h>
#include <mem_enum.h>
#include <gg_utility.h>

#include <io_enum.h>

#ifndef GGTEST_IO_HANDLER_H
#define GGTEST_IO_HANDLER_H

namespace gg_core::gg_mem {
    template <typename T>
    T IO_Read(MMU_Status* mmu, uint32_t addr) {
        // 04000000-040003FE   I/O Registers
        using namespace gg_io ;

        const uint32_t relativeAddr = addr - ioStart ;
        T result = 0 ;
        if (relativeAddr < E_RamSize::E_IO_SIZE) {
            mmu->_cycleCounter = IO_ACCESS_CYCLE();
            for (int i = 0 ; i < sizeof(T) ; ++i) {
                const auto curPolicy = static_cast<E_IO_AccessMode> (policyTable[relativeAddr + i]) ;
                result <<= 8 ;
                if (curPolicy == E_IO_AccessMode::R || curPolicy == E_IO_AccessMode::RW)
                    result |= mmu->IOReg[ relativeAddr + i ] ;
                else {
                    if (i == 0)
                        return mmu->IllegalReadValue() ;
                    else {
                        /*Do nothing, let the high 16bit value to be zero*/
                    } // else
                } // else
            } // for

            return result ;
        } // if
        else {
            // 04000400-04FFFFFF Not used
            NoUsed_Read<T>(mmu, addr);
            return mmu->IllegalReadValue() ;
        } // else
    } // IO_Read()

    template <typename T>
    void IO_Write(MMU_Status* mmu, uint32_t addr, T data) {
        // 04000000-040003FE   I/O Registers
        using namespace gg_io ;

        const uint32_t relativeAddr = addr - ioStart ;
        if (relativeAddr < E_RamSize::E_IO_SIZE) {
            mmu->_cycleCounter = IO_ACCESS_CYCLE();
            const auto curPolicy = static_cast<E_IO_AccessMode> (policyTable[relativeAddr]) ;
            if (curPolicy == E_IO_AccessMode::W || curPolicy == E_IO_AccessMode::RW) {
                // Just write the data directly, since we are reading IO by byte access(check policy per byte)
                // so direct write is safe.
                reinterpret_cast<T&>(mmu->IOReg.data() + relativeAddr) = data ;
                switch (relativeAddr) {
                    case 0x204:
                        mmu->UpdateWaitState() ;
                        break ;
                } // switch

                return ;
            } // if
            else {
                GGLOG(fmt::format(
                    "Attempt to WRITE {} value to READ-ONLY IO register 0x{:x}",
                    accessWidthName[ sizeof(T) >> 1 ],
                    addr
                ).c_str());
            } // else
        } // if

        NoUsed_Write(mmu, addr, data);
    } // IO_Write()
}

#endif //GGTEST_IO_HANDLER_H

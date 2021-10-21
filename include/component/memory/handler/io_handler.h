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
    T IO_Read(MMU_Status* mmu, uint32_t absAddr) {
        // 04000000-040003FE   I/O Registers
        using namespace gg_io ;

        const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart) ;
        T result = 0 ;
        if (relativeAddr < E_RamSize::E_IO_SIZE) {
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
            NoUsed_Read<T>(mmu, absAddr);
            return mmu->IllegalReadValue() ;
        } // else
    } // IO_Read()

    template <typename T>
    void IO_Write(MMU_Status* mmu, uint32_t absAddr, T data) {
        // 04000000-040003FE   I/O Registers
        using namespace gg_io ;

        const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart) ;
        if (relativeAddr < E_RamSize::E_IO_SIZE) {
            const auto curPolicy = static_cast<E_IO_AccessMode> (policyTable[relativeAddr]) ;
            if (curPolicy == E_IO_AccessMode::W || curPolicy == E_IO_AccessMode::RW) {
                // Just write the data directly, since we are reading IO by byte access(check policy per byte)
                // so direct write is safe.
                reinterpret_cast<T&>(mmu->IOReg[ relativeAddr ]) = data ;
                // handle io behavior which relative with mmu directly.
                switch (relativeAddr) {
                    case 0x204:
                        mmu->UpdateWaitState() ;
                        break ;
                } // switch

                return ;
            } // if
            else {
                mmu->logger->warn(
                    "Attempt to WRITE {} value to READ-ONLY IO register 0x{:x}",
                    accessWidthName[ sizeof(T) >> 1 ],
                    absAddr
                );
            } // else
        } // if

        NoUsed_Write(mmu, absAddr, data);
    } // IO_Write()
}

#endif //GGTEST_IO_HANDLER_H

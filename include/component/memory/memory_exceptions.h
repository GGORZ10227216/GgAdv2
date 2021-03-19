//
// Created by orzgg on 2021-03-08.
//

#include <cstdlib>

#include <mmu_status.h>
#include <cpu_status.h>

#ifndef GGTEST_MEMORY_EXCEPTIONS_H
#define GGTEST_MEMORY_EXCEPTIONS_H

namespace gg_core::gg_mem {
    struct InvalidAccessException : public std::exception {
        InvalidAccessException(gg_cpu::CPU_Status* cpuStatus, MMU_Status* mmuStatus, E_ErrorType errType) :
            _cpuStatus(cpuStatus), _mmuStatus(mmuStatus), _errType(errType)
        {
        }

        [[nodiscard]] const char *what() const noexcept override {
            return message.c_str();
        } // what()

        std::string message = "(empty)";
        const E_ErrorType _errType ;
    private:
        gg_cpu::CPU_Status* const _cpuStatus ;
        MMU_Status* const _mmuStatus ;
    };

    template <typename W>
    struct InvalidReadException : public InvalidAccessException {
        InvalidReadException(gg_cpu::CPU_Status* cpuStatus, MMU_Status* mmuStatus, E_ErrorType errType) :
            InvalidAccessException(cpuStatus, mmuStatus, errType)
        {
            switch (errType) {
                case BIOS_ACCESS_FROM_OUTSIDE:
                    break ;
                case ACCESS_INVALID_AREA:
                    break ;
                case SRAM_WIDTH_MISMATCH:
                    break ;
                default:
                    std::cerr << "Unknown memory error!!" << std::endl ;
                    std::exit(-1) ;
            } // switch
        }
    };

    template <typename W>
    struct InvalidWriteException : public InvalidAccessException {
        InvalidWriteException(gg_cpu::CPU_Status* cpuStatus, MMU_Status* mmuStatus, E_ErrorType errType) :
                InvalidAccessException(cpuStatus, mmuStatus, errType)
        {
            switch (errType) {
                case BIOS_ACCESS_FROM_OUTSIDE:
                    break ;
                case ACCESS_INVALID_AREA:
                    break ;
                case SRAM_WIDTH_MISMATCH:
                    break ;
                default:
                    std::cerr << "Unknown memory error!!" << std::endl ;
                    std::exit(-1) ;
            } // switch
        }
    };
}

#endif //GGTEST_MEMORY_EXCEPTIONS_H

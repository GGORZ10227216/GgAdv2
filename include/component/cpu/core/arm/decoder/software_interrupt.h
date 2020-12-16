//
// Created by buildmachine on 2020-11-30.
//

#include <cstdint>

#include <cpu_enum.h>

#ifndef GGTEST_SOFTWARE_INTERRUPT_H
#define GGTEST_SOFTWARE_INTERRUPT_H

namespace gg_core::gg_cpu {
    template <E_OperationMode OpMode>
    static void Interrupt_impl(GbaInstance &instance);

    template <uint32_t HashCode32>
    static constexpr auto SoftwareInterrupt() {
        return &Interrupt_impl<SVC> ;
    } // SoftwareInterrupt()
}

#endif //GGTEST_SOFTWARE_INTERRUPT_H

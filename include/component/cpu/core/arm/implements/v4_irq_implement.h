//
// Created by jason4_lee on 2020-09-30.
//

#include <cpu_enum.h>

#ifndef GGADV2_IRQ_API_H
#define GGADV2_IRQ_API_H

namespace gg_core::gg_cpu {
    template <E_OperationMode opMode>
    static void Interrupt_impl(CPU &instance) {
        const uint32_t preCPSR = instance.ReadCPSR() ;

        instance.WriteCPSR((preCPSR & ~0b11111u) | static_cast<uint8_t>(opMode)) ;
        instance.WriteSPSR(preCPSR) ;

        // both SVC & IRQ have same offset(4) in ARM mode
        instance._regs[ lr ] = instance._regs[ pc ] - 4 ;

        if constexpr (opMode == SVC)
            instance._regs[ pc ] = SW_IRQ ;
        else if constexpr (opMode == IRQ)
            instance._regs[ pc ] = HW_IRQ ;

        instance.RefillPipeline();

        instance.ChangeCpuMode(ARM);
        instance.SetI() ;
    } // Interrupt_impl()
}

#endif //GGADV2_IRQ_API_H

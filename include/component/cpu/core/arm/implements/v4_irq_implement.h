//
// Created by jason4_lee on 2020-09-30.
//

#include <cpu_enum.h>

#ifndef GGADV2_IRQ_API_H
#define GGADV2_IRQ_API_H

namespace gg_core::gg_cpu {
    template <E_OperationMode opMode>
    static void Interrupt_impl(CPU &instance) {
        instance.Fetch(&instance, gg_mem::N_Cycle) ;

        const uint32_t preCPSR = instance.ReadCPSR() ;

        instance.WriteCPSR((preCPSR & ~0b11111u) | static_cast<uint8_t>(opMode)) ;
        instance.WriteSPSR(preCPSR) ;

        instance._regs[ lr ] = instance._regs[ pc ] - instance.instructionLength ;

        if constexpr (opMode == SVC)
            instance._regs[ pc ] = SW_IRQ ;
        else if constexpr (opMode == IRQ)
            instance._regs[ pc ] = HW_IRQ ;

        instance.ChangeCpuMode(ARM);

        instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle);
        instance.SetI() ;
    } // Interrupt_impl()
}

#endif //GGADV2_IRQ_API_H

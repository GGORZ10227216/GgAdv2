//
// Created by jason4_lee on 2020-09-30.
//

#include <cpu_enum.h>

#ifndef GGADV2_IRQ_API_H
#define GGADV2_IRQ_API_H

namespace gg_core::gg_cpu {
    template <E_OperationMode opMode>
    static void Interrupt_impl(GbaInstance &instance) {
        instance._status._regs[ lr ] =
                instance._status.CurrentPC_OnExec() - (instance._status.GetCpuMode() == ARM ? 4 : 2) ;

        const uint32_t preCPSR = instance._status.ReadCPSR() ;

        instance._status.WriteCPSR((preCPSR & ~0b11111u) | static_cast<uint8_t>(opMode)) ;
        instance._status.WriteSPSR(preCPSR) ;

        if constexpr (opMode == SVC)
            instance._status._regs[ pc ] = SW_IRQ ;
        else if constexpr (opMode == IRQ)
            instance._status._regs[ pc ] = HW_IRQ ;

        instance.RefillPipeline() ;

        instance._status.ChangeCpuMode(ARM);
        instance._status.SetI() ;
    } // Interrupt_impl()
}

#endif //GGADV2_IRQ_API_H

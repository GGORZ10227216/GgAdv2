//
// Created by jason4_lee on 2020-09-30.
//

#include <cpu_enum.h>

#ifndef GGADV2_IRQ_API_H
#define GGADV2_IRQ_API_H

namespace gg_core::gg_cpu {
    template <E_OperationMode opMode>
    static void Interrupt_impl(CPUCore &self) {
        const uint32_t preCPSR = self.ReadCPSR() ;

        self.WriteCPSR((preCPSR & ~0b11111u) | static_cast<uint8_t>(opMode)) ;
        self.WriteSPSR(preCPSR) ;

        // both SVC & IRQ have same offset(4) in ARM mode
        self._regs[ lr ] = self._regs[ pc ] - 4 ;

        if constexpr (opMode == SVC)
            self._regs[ pc ] = SW_IRQ ;
        else if constexpr (opMode == IRQ)
            self._regs[ pc ] = HW_IRQ ;

        // fixme: check document
        self.RefillPipeline<ARM>() ;

        self.ChangeCpuMode(ARM);
        self.SetI() ;
    } // Interrupt_impl()
}

#endif //GGADV2_IRQ_API_H

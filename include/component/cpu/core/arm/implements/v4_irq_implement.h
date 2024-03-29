//
// Created by jason4_lee on 2020-09-30.
//

#include <cpu_enum.h>

#ifndef GGADV2_IRQ_API_H
#define GGADV2_IRQ_API_H

namespace gg_core::gg_cpu {
template<E_OperationMode opMode>
static void Interrupt_impl(CPU &instance) {
  const uint32_t preCPSR = instance.ReadCPSR();

  instance.WriteCPSR((preCPSR & ~0b11111u) | static_cast<uint8_t>(opMode));

  if constexpr (opMode == SVC) {
	instance._regs[lr] = instance._regs[pc] - instance.instructionLength;
	instance._regs[pc] = SW_IRQ;
  } // if
  else if constexpr (opMode == IRQ) {
	// Datasheet says:
	//   Where PC is the address of the instruction that was not executed because the FIQ or
	//   IRQ took priority ...
	//   ... Return instruction is "SUBS PC, R14_irq, #4"
	// According to that, I guess the correct lr value should be PC - 2*instructionLength + 4
	instance._regs[lr] = instance._regs[pc] - instance.instructionLength + 4;
	instance._regs[pc] = HW_IRQ;
  } // else if
  else {
	gg_core::Unreachable();
  }

  instance.WriteSPSR(preCPSR);

  instance.ChangeCpuMode(ARM);

  instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);
  instance.SetI(); // TODO: not sure setting the I bit is emulator's responsibility or programmer's
  //       Need to check what nintendo's BIOS do in interrupt routine.
} // Interrupt_impl()
}

#endif //GGADV2_IRQ_API_H


#ifndef GGADV2_V4_IRQ_IMPLEMENT
#define GGADV2_V4_IRQ_IMPLEMENT

namespace gg_core::gg_cpu {
    template <E_OperationMode opMode>
    void Interrupt(GbaInstance &instance, uint32_t nextInstructionAddr) {
        instance._status._regs[ lr ] = nextInstructionAddr ;

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
    }

    template <uint32_t HashCode32>
	void SoftwareInterrupt(GbaInstance& instance) {
        const uint32_t nextPC = instance._status.CurrentPC_OnExec() - (instance._status.GetCpuMode() == ARM ? 4 : 2);
        Interrupt<SVC>(instance, nextPC) ;
	}
} // gg_core::gg_cpu

#endif // GGADV2_V4_IRQ_IMPLEMENT
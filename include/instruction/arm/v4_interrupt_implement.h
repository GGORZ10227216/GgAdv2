#include <v4_irq_api.h>

namespace gg_core::gg_cpu {
	static void svc(GbaInstance& instance) {
        const uint32_t nextPC = instance._status.CurrentPC_OnExec() - (instance._status.GetCpuMode() == ARM ? 4 : 2);
        Interrupt<SVC>(instance, nextPC) ;
	}
} // gg_core::gg_cpu

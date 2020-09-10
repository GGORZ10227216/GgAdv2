//
// Created by orzgg on 2020-09-02.
//

#include <array>

#include <component_class.h>
#include <cpu_enum.h>
#include <status.h>

#ifndef GGADV_CPU_H
#define GGADV_CPU_H

namespace gg_core {
    class GbaInstance ;

    namespace gg_cpu {
        class Cpu : public ComponentClass<GbaInstance> {
            friend class Status;

        public :
            explicit Cpu(GbaInstance *framePtr);

        private :
            E_OperationMode opMode = SVC;
            E_CpuMode cpuMode = ARM;
            Regs regs;
            unsigned _cpsr = 0xd3;
            Status bank;
        };
    }
}

#endif //GGADV_CPU_H

//
// Created by orzgg on 2020-09-04.
//

#include <logger.h>

#include <gg_utility.h>
#include <bit_manipulate.h>

#include <cpu.h>
#include <mmu.h>
#include <timers.h>
#include <task_runner.h>

#ifndef GGADV_FRAMEWORK_BASE_H
#define GGADV_FRAMEWORK_BASE_H

namespace gg_core {
    struct GbaInstance {
        GbaInstance(const char* romPath);
        GbaInstance();

        uint64_t GetSystemClk() { return _systemClk ; }

        std::ostringstream oss ;
        sinkType logSink ;
        gg_mem::MMU mmu ;
        gg_cpu::CPU cpu ;

        gg_io::Timers timer;

        TaskRunner<64> runner;
        uint64_t _systemClk = 0 ;
    };
}


#endif //GGADV_FRAMEWORK_BASE_H

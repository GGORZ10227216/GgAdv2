//
// Created by orzgg on 2020-09-04.
//

#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_sinks.h>

using LOG = spdlog::sinks::null_sink_st ;
using sinkType = std::shared_ptr<LOG> ;
using loggerType = std::shared_ptr<spdlog::logger> ;

#include <gg_utility.h>
#include <bit_manipulate.h>

#include <cpu_enum.h>

#include <cpu_status.h>

#include <mmu.h>
#include <cpu.h>

#ifndef GGADV_FRAMEWORK_BASE_H
#define GGADV_FRAMEWORK_BASE_H

namespace gg_core {
    struct GbaInstance {
        GbaInstance(const char* romPath) :
            oss(),
            logSink(std::make_shared<LOG>()),
            mmu(romPath, logSink),
            cpu(mmu, logSink)
        {
        }

        std::ostringstream oss ;
        sinkType logSink ;
        gg_mem::MMU mmu ;
        gg_cpu::CPU cpu ;
    };
}


#endif //GGADV_FRAMEWORK_BASE_H

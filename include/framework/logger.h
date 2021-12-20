//
// Created by orzgg on 2020-09-02.
//

#include <string>
#include <utility>
#include <vector>
#include <array>
#include <chrono>

#include <optional>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_sinks.h>

using LOG = spdlog::sinks::null_sink_st ; // fixme: change me when release
using sinkType = std::shared_ptr<LOG> ;
using loggerType = std::shared_ptr<spdlog::logger> ;

#ifndef GGADV_LOGGER_H
#define GGADV_LOGGER_H

#endif //GGADV_LOGGER_H

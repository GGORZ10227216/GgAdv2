//
// Created by orzgg on 2020-09-02.
//

#include <logger.h>
#include <ctime>
#include <fmt/format.h>

using namespace std::chrono;

void gg_core::Logger::PrintLogs() {
    while (!_msgQueue.empty()) {
        const Msg &thisMsg = _msgQueue.front();
        std::time_t t = system_clock::to_time_t(thisMsg._timeStamp);
        fmt::print(stdout, "{} -> [{}] {}\n", std::ctime(&t),
                   Logger::_lvString[thisMsg._lv],
                   thisMsg._content
        );

        _msgQueue.pop() ;
    } // while
} // gg_core::logger::PrintLogs()
//
// Created by orzgg on 2020-09-02.
//

#include <string>
#include <utility>
#include <vector>
#include <array>
#include <chrono>

#ifndef GGADV_LOGGER_H
#define GGADV_LOGGER_H

namespace gg_core {
    struct Msg {
        enum E_Level { DEBUG, INFO, WARN, FATAL } ;
        const std::chrono::system_clock::time_point _timeStamp = std::chrono::system_clock::now() ;
        const E_Level _lv ;
        const std::string _content ;

        Msg(E_Level lv, std::string content) :
            _lv(lv), _content(std::move(content))
        {

        } // Msg()
    };

    class Logger {
    public :
        void Debug(const std::string& content) {
            _msgQueue.emplace_back(Msg::DEBUG, content) ;
        } // LogDebug()

        void Info(const std::string& content) {
            _msgQueue.emplace_back(Msg::INFO, content) ;
        } // LogInfo()

        void Warning(const std::string& content) {
            _msgQueue.emplace_back(Msg::WARN, content) ;
        }

        void Fatal(const std::string& content) {
            _msgQueue.emplace_back(Msg::FATAL, content ) ;
        }

        virtual void PrintLogs() ;
    private :
        constexpr static std::array<const char*, 4> _lvString {
            "DEBUG","INFO","WARN","FATAL"
        } ;

        std::vector<Msg> _msgQueue ;
    };
}

#endif //GGADV_LOGGER_H

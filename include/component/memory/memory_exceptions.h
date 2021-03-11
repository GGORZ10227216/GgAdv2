//
// Created by orzgg on 2021-03-08.
//

#ifndef GGTEST_MEMORY_EXCEPTIONS_H
#define GGTEST_MEMORY_EXCEPTIONS_H

namespace gg_core::gg_mem {
    struct InvalidAccessException : public std::exception {
        explicit InvalidAccessException(unsigned width, uint32_t addr, std::string&& whatMsg) :
                _accessType(READ),
                _addr(addr),
                _data(0x00000000),
                _accessWidth(width),
                message(whatMsg)
        {
        }

        explicit InvalidAccessException(unsigned width, uint32_t addr, uint32_t data, std::string&& whatMsg) :
                _accessType(WRITE),
                _addr(addr),
                _data(data),
                _accessWidth(width),
                message(whatMsg)
        {
        }

        [[nodiscard]] const char *what() const noexcept override {
            return message.c_str();
        } // what()

        const E_AccessType _accessType ;
        const uint32_t _addr, _data;
        const unsigned _accessWidth ;
        std::string message = "(empty)";
    };
}

#endif //GGTEST_MEMORY_EXCEPTIONS_H

//
// Created by buildmachine on 2020-10-29.
//

#include <type_traits>

#ifndef GGTEST_GG_UTILITY_H
#define GGTEST_GG_UTILITY_H

namespace gg_core {
    template <typename T = void>
    inline void Unreachable() {
        static_assert(!std::is_same_v<T,T>, "Unreachable code has been instantiated.");
    }

    template <typename T, typename... Args>
    constexpr auto MakeArray(Args... args) {
        return std::array<T, sizeof...(args)> { args... } ;
    }
}

#endif //GGTEST_GG_UTILITY_H

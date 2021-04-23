//
// Created by buildmachine on 2020-10-29.
//

#include <type_traits>
#include <logger.h>

#ifndef GGTEST_GG_UTILITY_H
#define GGTEST_GG_UTILITY_H

namespace gg_core {
    template<typename T = void>
    inline void Unreachable() {
        static_assert(!std::is_same_v<T, T>, "Unreachable code has been instantiated.");
    }

    template<typename... T>
    constexpr auto make_array(T &&... values) ->
    std::array<
            typename std::decay<
                    typename std::common_type<T...>::type>::type,
            sizeof...(T)> {
        return {std::forward<T>(values)...};
    }

    template<typename T, typename U>
    constexpr bool SameSize() {
        return sizeof(T) == sizeof(U);
    }

    inline void Unimplemented(const std::string& what) {
        std::cerr << "Unimplemented: " << what << std::endl ;
        exit(-1) ;
    }

    template <typename T>
    static inline void GG_DEBUG(const char* what, T* self) {
        // temporary implement
        self->logger.Debug(what) ;
    }
}

#endif //GGTEST_GG_UTILITY_H

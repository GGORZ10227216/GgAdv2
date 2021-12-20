//
// Created by buildmachine on 2021-03-17.
//

#ifndef GGTEST_HANDLER_TABLE_H
#define GGTEST_HANDLER_TABLE_H

namespace gg_core::gg_mem {
    using ReadHandler = std::tuple<
        uint8_t (*)(GbaInstance&, uint32_t),
        uint16_t(*)(GbaInstance&, uint32_t),
        uint32_t(*)(GbaInstance&, uint32_t)
    >;

    using WriteHandler = std::tuple<
        void(*)(GbaInstance&, uint32_t, uint8_t),
        void(*)(GbaInstance&, uint32_t, uint16_t),
        void(*)(GbaInstance&, uint32_t, uint32_t)
    >;
}

#endif //GGTEST_HANDLER_TABLE_H

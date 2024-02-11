//
// Created by buildmachine on 2021-03-17.
//

#include <cstdint>
#include <tuple>

#ifndef GGTEST_HANDLER_TABLE_H
#define GGTEST_HANDLER_TABLE_H

namespace gg_core::gg_mem {
class MMU;

// I/O register only allow byte access
using IOReadHandler = uint8_t (*)(GbaInstance &, uint32_t);
using IOWriteHandler = void (*)(GbaInstance &, uint32_t, uint8_t);

using ByteMMUReadHandler = uint8_t (MMU::*)(uint32_t);
using WordMMUReadHandler = uint16_t (MMU::*)(uint32_t);
using DWordMMUReadHandler = uint32_t (MMU::*)(uint32_t);
using MMUReadHandler = std::tuple<ByteMMUReadHandler, WordMMUReadHandler, DWordMMUReadHandler>;

using ByteMMUWriteHandler = void (MMU::*)(uint32_t, uint8_t);
using WordMMUWriteHandler = void (MMU::*)(uint32_t, uint16_t);
using DWordMMUWriteHandler = void (MMU::*)(uint32_t, uint32_t);
using MMUWriteHandler = std::tuple<ByteMMUWriteHandler, WordMMUWriteHandler, DWordMMUWriteHandler>;
}

#endif //GGTEST_HANDLER_TABLE_H

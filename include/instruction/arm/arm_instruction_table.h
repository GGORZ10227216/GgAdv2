#include <array>
#include <arm_decoder.h>
#include <type_traits>

namespace gg_core::gg_cpu {
    constexpr auto armHandlers =
            GetArmInstructionTable(std::make_index_sequence<4096>{}) ;
}

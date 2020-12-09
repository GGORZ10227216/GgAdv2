//
// Created by orzgg on 2020-11-21.
//

#include <cstdint>
#include <type_traits>
#include <utility>
#include <array>

#include <decoder/data_processing.h>
#include <decoder/multiply.h>
#include <decoder/memory_access.h>
#include <decoder/software_interrupt.h>
#include <decoder/psr_transfer.h>
#include <decoder/branch.h>

#ifndef GGTEST_ARM_HANDLER_H
#define GGTEST_ARM_HANDLER_H

namespace gg_core {
    class GbaInstance ;

    namespace gg_cpu {
        void UndefinedHandler(GbaInstance &instance) {
            std::cout << "Execute a undefined instruction." << std::endl ;
            exit(-2) ;
        }

        using HandlerType = decltype(&UndefinedHandler) ;

        template <uint32_t HashCode12>
        constexpr inline auto DecodeARM() -> HandlerType
        {
            constexpr uint32_t HashCode32 = ((HashCode12 & 0xff0) << 16) | ((HashCode12 & 0xf) << 4);

            if constexpr ((HashCode12 & 0b1111'0000'0000) == 0b1111'0000'0000)
                return SoftwareInterrupt<HashCode32>();
            if constexpr ((HashCode12 & 0b1110'0000'0000) == 0b1010'0000'0000)
                return Branch<HashCode32>();
            if constexpr ((HashCode12 & 0b1110'0000'0000) == 0b1000'0000'0000)
                return BlockDataTransfer<HashCode32>();
            if constexpr ((HashCode12 & 0b1110'0000'0001) == 0b0110'0000'0001)
                return UndefinedHandler;
            if constexpr ((HashCode12 & 0b1100'0000'0000) == 0b0100'0000'0000)
                return SingleDataTransfer<HashCode32>();
            if constexpr ((HashCode12 & 0b1111'1111'1111) == 0b0001'0010'0001) {
                /*
                 * TODO: The safe mode of our interpreter :
                 *
                 * The hash code 0x121 is may be a undefined instruction if
                 * instruction[19:4] are not all ONE.
                 *
                 * We "CAN NOT" detect this problem in compile time since we only
                 * use instruction[27:20] and instruction[7:4] (total 12 bits)
                 * to decode the instruction.
                 *
                 * We should design a mechanism to perform a check in execute time when user
                 * think he/she is running a gba program that probably has undefined
                 * instruction.
                 * */
                return BranchExchange();
            } // if
            if constexpr ((HashCode12 & 0b1111'1100'1111) == 0b0000'0000'1001)
                return Multiply<HashCode32>();
            if constexpr ((HashCode12 & 0b1111'1000'1111) == 0b0000'1000'1001)
                return MultiplyLong<HashCode32>();
            if constexpr ((HashCode12 & 0b1111'1011'1111) == 0b0001'0000'1001)
                return Swap<HashCode32>();
            if constexpr ((HashCode12 & 0b1110'0000'1001) == 0b0000'0000'1001) {
                uint32_t opcode = (HashCode12 & 0b110) >> 1 ;
                return opcode == 0b00 ? UndefinedHandler : HalfDataTransfer<HashCode32>();
            } // if constexpr
            if constexpr ((HashCode12 & 0b1101'1001'0000) == 0b0001'0000'0000)
                return PSR_Transfer<HashCode32>();
            if constexpr ((HashCode12 & 0b1100'0000'0000) == 0b0000'0000'0000) {
                auto NoResult = []() {
                    constexpr uint32_t opcode = (HashCode12 & 0x1e0) >> 5;
                    if (opcode >= 0b1000 && opcode <= 0b1011)
                        return true ;
                    return false ;
                };

                if (NoResult() && !TestBit(HashCode12, 4))
                    return UndefinedHandler;

                return DataProcessing<HashCode32>();
            } // if constexpr

            return UndefinedHandler ;
        }

        template <size_t... Idx>
        constexpr auto GetArmInstructionTable(std::index_sequence<Idx...>)
        -> std::array<HandlerType, sizeof...(Idx)>
        {
            constexpr std::array<HandlerType, sizeof...(Idx)> result{
                    DecodeARM<Idx>()...
            } ;
            return result ;
        }

        constexpr static auto armHandlers =
                GetArmInstructionTable(std::make_index_sequence<4096>{}) ;
    }
}

#endif //GGTEST_ARM_HANDLER_H

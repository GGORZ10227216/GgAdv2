//
// Created by orzgg on 2020-11-21.
//

#include <cstdint>
#include <type_traits>
#include <utility>
#include <array>

#include <bit_manipulate.h>

#ifndef GGTEST_ARM_HANDLER_H
#define GGTEST_ARM_HANDLER_H

namespace gg_core::gg_cpu {
    class GbaInstance ;

    template <uint32_t HashCode32>
    void DataProcessing(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void PSR_Transfer(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void Multiply(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void MultiplyLong(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void Interrupt(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void Branch(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void BranchAndExchange(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void BlockTransfer(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void Undefined(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void SingleDataTransfer(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void HalfDataTransfer(GbaInstance &instance) ;

    template <uint32_t HashCode32>
    void Swap(GbaInstance &instance) ;

    using HandlerType = decltype(&Undefined<0>) ;

    template <uint32_t HashCode12>
    constexpr inline auto DecodeARM() -> HandlerType {
        constexpr uint32_t HashCode32 = ((HashCode12 & 0xff0) << 16) | ((HashCode12 & 0xf) << 4);

        if constexpr ((HashCode12 & 0b1111'0000'0000) == 0b1111'0000'0000)
            return &Interrupt<HashCode32>;
        if constexpr ((HashCode12 & 0b1110'0000'0000) == 0b1010'0000'0000)
            return &Branch<HashCode32>;
        if constexpr ((HashCode12 & 0b1110'0000'0000) == 0b1000'0000'0000)
            return &BlockTransfer<HashCode32>;
        if constexpr ((HashCode12 & 0b1110'0000'0001) == 0b0110'0000'0001)
            return &Undefined<0>;
        if constexpr ((HashCode12 & 0b1100'0000'0000) == 0b0100'0000'0000)
            return &SingleDataTransfer<HashCode32>;
        if constexpr ((HashCode12 & 0b1111'1111'1111) == 0b0001'0010'0001)
            return &BranchAndExchange<HashCode32>;
        if constexpr ((HashCode12 & 0b1111'1100'1111) == 0b0000'0000'1001)
            return &Multiply<HashCode32>;
        if constexpr ((HashCode12 & 0b1111'1000'1111) == 0b0000'1000'1001)
            return &MultiplyLong<HashCode32>;
        if constexpr ((HashCode12 & 0b1111'1011'1111) == 0b0001'0000'1001)
            return &Swap<HashCode32>;
        if constexpr ((HashCode12 & 0b1110'0000'1001) == 0b0000'0000'1001) {
            uint32_t opcode = (HashCode12 & 0b110) >> 1 ;
            return opcode == 0b00 ? &Undefined<1> : &HalfDataTransfer<HashCode32>;
        } // if constexpr
        if constexpr ((HashCode12 & 0b1101'1001'0000) == 0b0001'0000'0000)
            return &PSR_Transfer<HashCode32>;
        if constexpr ((HashCode12 & 0b1100'0000'0000) == 0b0000'0000'0000) {
            auto NoResult = []() {
                constexpr uint32_t opcode = (HashCode12 & 0x1e0) >> 4;
                if (opcode >= 0b1000 && opcode <= 0b1011)
                    return true ;
                return false ;
            };

            if (NoResult() && !TestBit(HashCode12, 4))
                return &Undefined<2>;

            return &DataProcessing<HashCode32>;
        } // if constexpr

        return &Undefined<3>;
    }

    constexpr int test() {return 0 ;}

    template <size_t... Idx>
    constexpr auto GetArmInstructionTable(std::index_sequence<Idx...>)
        -> std::array<HandlerType, sizeof...(Idx)>
    {
        constexpr std::array<HandlerType, sizeof...(Idx)> result{
            DecodeARM<Idx>()...
        } ;
        return result ;
    }
}

#endif //GGTEST_ARM_HANDLER_H

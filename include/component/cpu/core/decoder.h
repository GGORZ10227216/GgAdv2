//
// Created by orzgg on 2020-11-21.
//

#include <iostream>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <array>

#include <arm/decoder/data_processing.h>
#include <arm/decoder/multiply.h>
#include <arm/decoder/memory_access.h>
#include <arm/decoder/software_interrupt.h>
#include <arm/decoder/psr_transfer.h>
#include <arm/decoder/branch.h>

#include <thumb/decoder/type1.h>
#include <thumb/decoder/type2.h>
#include <thumb/decoder/type3.h>
#include <thumb/decoder/type4.h>
#include <thumb/decoder/type5.h>
#include <thumb/decoder/type6.h>
#include <thumb/decoder/type7.h>
#include <thumb/decoder/type8.h>
#include <thumb/decoder/type9.h>
#include <thumb/decoder/type10.h>
#include <thumb/decoder/type11.h>
#include <thumb/decoder/type12.h>
#include <thumb/decoder/type13.h>
#include <thumb/decoder/type14.h>
#include <thumb/decoder/type15.h>
#include <thumb/decoder/type16.h>
#include <thumb/decoder/type17.h>
#include <thumb/decoder/type18.h>
#include <thumb/decoder/type19.h>

#ifndef GGTEST_ARM_HANDLER_H
#define GGTEST_ARM_HANDLER_H

namespace gg_core {
    namespace gg_cpu {
        static void UndefinedHandler(CPU &instance) {
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
                constexpr uint32_t SH_Bit = (HashCode12 & 0b110) >> 1 ;
                constexpr bool isLDR = HashCode12 & gg_core::_BV(4) ;
                constexpr bool isUndefined = isLDR ? (SH_Bit == 0b00) : (SH_Bit != 0b01) ;

                if constexpr (isUndefined)
                    return UndefinedHandler ;
                else
                    return HalfDataTransfer<HashCode32>() ;
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

        constexpr static auto ARM_HandlerTable =
                GetArmInstructionTable(std::make_index_sequence<4096>{}) ;

        // todo: Thumb decoder
        template <uint32_t HashCode10>
        constexpr inline auto DecodeThumb() -> HandlerType
        {
            constexpr unsigned firstStageCode = (HashCode10 & 0b1110'0000'00) >> 7;
            if constexpr (firstStageCode == 0b000) {
                constexpr unsigned Op = (HashCode10 & 0b0001'1000'00) >> 5 ;
                if constexpr (Op == 0b11)
                return ThumbType2<HashCode10>() ;
                else
                    return ThumbType1<HashCode10>() ;
            } // if
            else if constexpr (firstStageCode == 0b001) {
                return ThumbType3<HashCode10>() ;
            } // else if
            else if constexpr (firstStageCode == 0b010) {
                constexpr unsigned secondStageCode = (HashCode10 & 0b0001'1100'00) >> 4;
                if constexpr (secondStageCode == 0b000) {
                    return ThumbType4<HashCode10>() ;
                } // if
                else if constexpr (secondStageCode == 0b001) {
                    return ThumbType5<HashCode10>() ;
                } // else if
                else if constexpr (secondStageCode == 0b010 || secondStageCode == 0b011) {
                    return ThumbType6<HashCode10>() ;
                } // else
                else {
                    constexpr unsigned thirdStageCode = (HashCode10 & 0b0000'0010'00) >> 3 ;
                    if constexpr (thirdStageCode == 0) {
                        return ThumbType7<HashCode10>() ;
                    } // if
                    else {
                        return ThumbType8<HashCode10>() ;
                    } // else
                } // return
            } // else if
            else if constexpr (firstStageCode == 0b011) {
                return ThumbType9<HashCode10>() ;
            } // else if
            else if constexpr (firstStageCode == 0b100) {
                constexpr unsigned secondStageCode = (HashCode10 & 0b0001'0000'00) >> 6;
                if constexpr (secondStageCode == 0)
                return ThumbType10<HashCode10>() ;
                else
                    return ThumbType11<HashCode10>() ;
            } // else if
            else if (firstStageCode == 0b101) {
                constexpr unsigned secondStageCode = (HashCode10 & 0b0001'0000'00) >> 6;
                if constexpr (secondStageCode == 0)
                return ThumbType12<HashCode10>() ;
                else {
                    constexpr unsigned thirdStageCode = (HashCode10 & 0b0000'0100'00) >> 4 ;
                    if constexpr (thirdStageCode == 0)
                    return ThumbType13<HashCode10>() ;
                    else
                        return ThumbType14<HashCode10>() ;
                } // else
            } // else if
            else if constexpr (firstStageCode == 0b110) {
                constexpr bool bit6 = TestBit(HashCode10, 6) ;
                if constexpr (bit6) {
                    constexpr unsigned cond = (HashCode10 & (0b1111 << 2)) >> 2 ;
                    if constexpr (cond == 0b1111)
                    return ThumbType17<HashCode10>() ;
                    else
                        return ThumbType16<HashCode10>() ;
                } // if
                else {
                    return ThumbType15<HashCode10>() ;
                } // else
            } // else if
            else if constexpr (firstStageCode == 0b111){
                constexpr bool bit6 = TestBit(HashCode10, 6) ;
                if constexpr (bit6)
                return ThumbType19<HashCode10>();
                else
                    return ThumbType18<HashCode10>();
            } // else

            return UndefinedHandler ;
        }

        template <size_t... Idx>
        constexpr auto GetThumbInstructionTable(std::index_sequence<Idx...>)
        -> std::array<HandlerType, sizeof...(Idx)>
        {
            constexpr std::array<HandlerType, sizeof...(Idx)> result{
                DecodeThumb<Idx>()...
            } ;

            return result ;
        }

        constexpr static auto Thumb_HandlerTable =
                GetThumbInstructionTable(std::make_index_sequence<1024>{}) ;
    }
}

#endif //GGTEST_ARM_HANDLER_H

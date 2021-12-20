//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <bit_manipulate.h>

#include <cpu_enum.h>
#include <display_memory.h>

#include <cpu_status.h>
#include <mmu_status.h>
#include <handler/handler_table.h>

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core {
    class GbaInstance;

    namespace gg_mem {
        template<typename T>
        T NoUsed_Read(GbaInstance& instance, uint32_t absAddr);

        template<typename T>
        void NoUsed_Write(GbaInstance& instance, uint32_t absAddr, T data);

        template<typename W>
        inline unsigned CountAccessRotate(uint32_t addr) {
            if constexpr (SameSize<W, BYTE>())
                return 0;
            else if constexpr (SameSize<W, WORD>())
                return (addr & 0x1) << 3;
            else if constexpr (SameSize<W, DWORD>())
                return (addr & 0x3) << 3;
            else
                gg_core::Unreachable();
        } // AddrAlign()

        class MMU : public MMU_Status {
        public :
            MMU(GbaInstance& instance, const std::optional<std::filesystem::path> &romPath);

            uint8_t Read8(unsigned addr) {
                return Read<uint8_t>(addr, N_Cycle);
            } // Read8()

            uint32_t Read16(unsigned addr) {
                // fixed return type to uint32_t, see Read<uint16_t>()
                // for detail.
//            const unsigned rotate = CountAccessRotate<WORD>(addr);
                uint32_t result = Read<uint16_t>(addr, N_Cycle);
                return result;
            } // Read16()

            uint32_t Read32(unsigned addr) {
//            const unsigned rotate = CountAccessRotate<DWORD>(addr);
                uint32_t result = Read<uint32_t>(addr, N_Cycle);
                return result;
            } // Read32()

            template<typename T>
            void Write8(unsigned addr, T value) requires std::is_same_v<T, uint8_t> {
                Write<uint8_t>(addr, value, gg_mem::S_Cycle);
            } // Write()

            template<typename T>
            void Write16(unsigned addr, T value) requires std::is_same_v<T, uint16_t> {
                Write<uint16_t>(addr, value, gg_mem::S_Cycle);
            } // Write()

            template<typename T>
            void Write32(unsigned addr, T value) requires std::is_same_v<T, uint32_t> {
                Write<uint32_t>(addr, value, gg_mem::S_Cycle);
            } // Write()

            inline int CalculateCycle(uint32_t absAddr, int accessWidth, E_AccessType accessType) {
                return memCycleTable[absAddr >> 24][accessType].cycle[accessWidth] ; ;
            } // CalculateCycle()

            template<typename W, typename T>
            void Write(uint32_t absAddr, T value, E_AccessType accessType) requires std::is_same_v<W, T> {
                const uint32_t alignedAddr = AlignAddr<W>(absAddr);
                unsigned addrTrait = (alignedAddr & 0xff000000) >> 24;
                requestAccessType = accessType ;

                if (addrTrait > 0xf) {
                    NoUsed_Write<W>(_instance, alignedAddr, value) ;
                    _cycleCounter += 1 ;
                } // if
                else {
                    std::get<(sizeof(W) >> 1)>(WriteHandlers[ addrTrait ])(_instance, alignedAddr, value) ;
                    _cycleCounter += accessType == I_Cycle ? 1 : CalculateCycle(absAddr, sizeof(W), accessType) ;
                } // else

                lastAccessAddr = absAddr ;
            } // Write()

            template<typename W>
            uint32_t Read(uint32_t absAddr, E_AccessType accessType) {
                // Strange behavior of "Read WORD from unaligned address":
                // According to the NO$GBA's behavior, 16bit read still need
                // rotating. And address is aligned to 16bit bus.
                // But rotating result is affect to "whole 32bit register",
                // that means we need to fixed the return type of Read() to 32bit
                // const uint32_t alignedAddr = AlignAddr<W>(addr);
                unsigned addrTrait = (absAddr & 0xff000000) >> 24;
                uint32_t result = 0 ;
                requestAccessType = accessType ;

                if (addrTrait > 0xf) {
                    result = NoUsed_Read<W>(_instance, absAddr) ;
                    _cycleCounter += 1 ;
                } // if
                else {
                    result = std::get<(sizeof(W) >> 1)>(ReadHandlers[ addrTrait ])(_instance, absAddr) ;
                    _cycleCounter += accessType == I_Cycle ? 1 : CalculateCycle(absAddr, sizeof(W), accessType) ;
                } // else

                lastAccessAddr = absAddr ;
                if constexpr (sizeof(W) == 1)
                    return result ;
                else {
                    const unsigned rotate = CountAccessRotate<W>(absAddr);
                    return rotr(result, rotate);
                } // else
            } // Read()

            GbaInstance& _instance;
            static std::array<ReadHandler, 16> ReadHandlers;
            static std::array<WriteHandler, 16> WriteHandlers;
        };
    }
}

#endif //GGADV_MMU_H

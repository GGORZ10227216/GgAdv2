//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <bit_manipulate.h>
#include <display_memory.h>
#include <gamepak_memory.h>
#include <general_memory.h>
#include <gg_utility.h>
#include <mem_enum.h>

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core {
    class GbaInstance;

    namespace gg_mem {
        template <E_AccessWidth W>
        inline unsigned AddrAlign(uint32_t addr) {
            if constexpr (W == BYTE)
                return addr ;
            else if constexpr (W == WORD)
                return addr & ~0x1 ;
            else if constexpr (W == DWORD)
                return addr & ~0x3 ;
            else
                gg_core::Unreachable() ;
        } // AddrAlign()

        template <E_AccessWidth W>
        inline unsigned CountAccessRotate(uint32_t addr) {
            if constexpr (W == BYTE)
                return 0 ;
            else if constexpr (W == WORD)
                return (addr & 0x1) << 3 ;
            else if constexpr (W == DWORD)
                return (addr & 0x3) << 3 ;
            else
                gg_core::Unreachable() ;
        } // AddrAlign()

        class MMU {
        public :
            MMU(const std::optional<std::filesystem::path> &romPath) :
                    general(_cycleCounter),
                    display(_cycleCounter),
                    gamepak(romPath, _cycleCounter)
            {
            }

            uint8_t Read8(unsigned addr) {
                return Access(addr, BYTE);
            } // Read8()

            uint16_t Read16(unsigned addr) {
                const unsigned addrAligned = AddrAlign<WORD>(addr);
                const unsigned rotate = CountAccessRotate<WORD>(addr);
                uint16_t result = reinterpret_cast<uint16_t &> (Access(addrAligned, WORD));
                return rotr(result, rotate);
            } // Read16()

            uint32_t Read32(unsigned addr) {
                const unsigned addrAligned = AddrAlign<DWORD>(addr);
                const unsigned rotate = CountAccessRotate<DWORD>(addr);

                uint8_t& tmpRef = Access(addrAligned, DWORD) ;
                uint32_t result = reinterpret_cast<uint32_t &> (tmpRef);

                return rotr(result, rotate);
            } // Read32()

            template<typename T>
            void Write8(unsigned addr, T value) requires std::is_same_v<T, uint8_t> {
                Access(addr, BYTE) = value;
            } // Write()

            template<typename T>
            void Write16(unsigned addr, T value) requires std::is_same_v<T, uint16_t> {
//                if (addr % 2 != 0) {
//                    // todo: log warning msg
//                } // if

                reinterpret_cast<uint16_t &> (Access(AddrAlign<WORD>(addr), WORD)) = value;
            } // Write()

            template<typename T>
            void Write32(unsigned addr, T value) requires std::is_same_v<T, uint32_t> {
//                if (addr % 4 != 0) {
//                    // todo: log warning msg
//                } // if

                reinterpret_cast<uint32_t &> (Access(AddrAlign<DWORD>(addr), DWORD)) = value;
            } // Write()

        private :
            uint8_t &Access(unsigned addr, E_AccessWidth width) {
                if (addr >= 0x0 && addr <= 0x4ffffff) {
                    return general.Access(addr, width);
                } // if
                else if (addr >= 0x5000000 && addr <= 0x7FFFFFF) {
                    return display.Access(addr, width);
                } // else if
                else if (addr >= 0x8000000 && addr <= 0xFFFFFFF) {
                    return gamepak.Access(addr, width);
                } // else if

                // fixme: out of bound
                return general.Access(addr, width);
            } // Access()

            GeneralMemory general;
            DisplayMemory display;
            GamepakMemory gamepak;

            unsigned _cycleCounter = 0;
        };
    }
}

#endif //GGADV_MMU_H

//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <bit_manipulate.h>
#include <display_memory.h>
#include <gamepak_memory.h>
#include <general_memory.h>
#include <mem_enum.h>

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core {
    class GbaInstance;

    namespace gg_mem {
        class MMU {
        public :
            MMU(const std::optional<std::filesystem::path> &romPath) :
                    general(_cycleCounter),
                    display(_cycleCounter),
                    gamepak(romPath, _cycleCounter) {
                general.Access(0, BYTE);
            }

            uint8_t Read8(unsigned addr) {
                return Access(addr, BYTE);
            } // Read8()

            uint16_t Read16(unsigned addr) {
                constexpr unsigned align = 2;
                const unsigned addrAligned = AddrAlign(addr, align);
                const unsigned rotate = (addrAligned - addr) * 8;
                uint16_t result = reinterpret_cast<uint16_t &> (Access(addrAligned, WORD));
                return rotr(result, rotate);
            } // Read16()

            uint32_t Read32(unsigned addr) {
                constexpr unsigned align = 4;
                const unsigned addrAligned = AddrAlign(addr, align);
                const unsigned rotate = (addrAligned - addr) * 8;
                uint32_t result = reinterpret_cast<uint32_t &> (Access(addrAligned, DWORD));
                return rotr(result, rotate);
            } // Read16()

            template<typename T>
            void Write8(unsigned addr, T value) requires std::is_same_v<T, uint8_t> {
                Access(addr, BYTE) = value;
            } // Write()

            template<typename T>
            void Write16(unsigned addr, T value) requires std::is_same_v<T, uint16_t> {
                if (addr % 2 != 0) {
                    // todo: log warning msg
                } // if

                reinterpret_cast<uint16_t &> (Access(AddrAlign(addr, 2), WORD)) = value;
            } // Write()

            template<typename T>
            void Write32(unsigned addr, T value) requires std::is_same_v<T, uint32_t> {
                if (addr % 4 != 0) {
                    // todo: log warning msg
                } // if

                reinterpret_cast<uint32_t &> (Access(AddrAlign(addr, 4), DWORD)) = value;
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

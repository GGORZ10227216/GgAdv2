//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <gg_utility.h>
#include <bit_manipulate.h>
#include <mem_enum.h>
#include <mmu_status.h>
#include <display_memory.h>
#include <gamepak_memory.h>
#include <general_memory.h>
#include <memory_exceptions.h>
#include <handler/handler_table.h>
#include <io.h>

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core::gg_mem {
    // todo: invalid memory access handle
    // todo: mmu refactoring

    template<typename W>
    inline unsigned AlignAddr(uint32_t addr) {
        if constexpr (SameSize<W, BYTE>())
            return addr;
        else if constexpr (SameSize<W, WORD>())
            return addr & ~0x1;
        else if constexpr (SameSize<W, DWORD>())
            return addr & ~0x3;
        else
            gg_core::Unreachable();
    } // AddrAlign()

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
        MMU(const std::optional<std::filesystem::path> &romPath):
            MMU_Status(romPath.value().c_str())
        {
            // fixme: leave bios data to all zero for debugging
            bios_data.fill(0);
            // memcpy( bios_data.data(), biosData.data(), biosData.size() ) ;

            // fixme: open all gamepak memory area for debug only
            ROM_WS0.reserve(0x2000000);
            ROM_WS1.reserve(0x2000000);
            ROM_WS2.reserve(0x2000000);
        }

        uint8_t Read8(unsigned addr) {
            return Read<uint8_t>(addr);
        } // Read8()

        uint16_t Read16(unsigned addr) {
            return Read<uint16_t>(addr);
        } // Read16()

        uint32_t Read32(unsigned addr) {
            const unsigned rotate = CountAccessRotate<DWORD>(addr);
            uint32_t result = Read<uint32_t>(addr);
            return rotr(result, rotate);
        } // Read32()

        template<typename T>
        void Write8(unsigned addr, T value) requires std::is_same_v<T, uint8_t> {
//                _Access<WRITE,BYTE>() = value;
            Write<uint8_t>(addr, value);
        } // Write()

        template<typename T>
        void Write16(unsigned addr, T value) requires std::is_same_v<T, uint16_t> {
            Write<uint16_t>(addr, value);
        } // Write()

        template<typename T>
        void Write32(unsigned addr, T value) requires std::is_same_v<T, uint32_t> {
//                reinterpret_cast<uint32_t &> (_Access<WRITE, DWORD>()) = value;
            Write<uint32_t>(addr, value);
        } // Write()

        template<typename W, typename T>
        void Write(uint32_t addr, T value) requires std::is_same_v<W, T> {
            try {
                _addrBus = addr;
                _dataBus = value;
                reinterpret_cast<W &> (_Access<WRITE, W>()) = value;
            } catch (InvalidAccessException &e) {
                std::cout << e.what() << std::endl;
                IllegalWriteBehavior(e._errType);
            }
        } // Write()

        template<typename W>
        W Read(uint32_t addr) {
            const uint32_t alignedAddr = AlignAddr<W>(addr);
            const unsigned addrTrait = (alignedAddr & 0x0f000000) >> 24;
            return std::get<(sizeof(W) >> 1)>(ReadHandlers[ addrTrait ])(this, addr) ;
        } // Write()
    };
}

#endif //GGADV_MMU_H

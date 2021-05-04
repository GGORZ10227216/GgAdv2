//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <mem_enum.h>
#include <mmu_status.h>
#include <gamepak_memory.h>
#include <general_memory.h>
#include <memory_exceptions.h>
#include <handler/handler_table.h>

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core::gg_mem {
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
        MMU(const std::optional<std::filesystem::path> &romPath, sinkType& sink):
            MMU_Status(romPath, sink)
        {
            memcpy( bios_data.data(), biosData.data(), biosData.size() ) ;
        }

        uint8_t Read8(unsigned addr) {
            return Read<uint8_t>(addr);
        } // Read8()

        uint32_t Read16(unsigned addr) {
            // fixed return type to uint32_t, see Read<uint16_t>()
            // for detail.
            const unsigned rotate = CountAccessRotate<WORD>(addr);
            uint32_t result = Read<uint16_t>(addr);
            return rotr(result, rotate);
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
            const uint32_t alignedAddr = AlignAddr<W>(addr);
            unsigned addrTrait = (alignedAddr & 0xff000000) >> 24;

            if (addrTrait > 0xf)
                NoUsed_Write<W>(this, alignedAddr, value) ;

            std::get<(sizeof(W) >> 1)>(WriteHandlers[ addrTrait ])(this, alignedAddr, value) ;
        } // Write()

        template<typename W>
        uint32_t Read(uint32_t addr) {
            // Strange behavior of "Read WORD from unaligned address":
            // According to the NO$GBA's behavior, 16bit read still need
            // rotating. And address is aligned to 16bit bus.
            // But rotating result is affect to "whole 32bit register",
            // that means we need to fixed the return type of Read() to 32bit
            const uint32_t alignedAddr = AlignAddr<W>(addr);
            unsigned addrTrait = (alignedAddr & 0xff000000) >> 24;

            if (addrTrait > 0xf)
                return NoUsed_Read<W>(this, alignedAddr) ;

            return std::get<(sizeof(W) >> 1)>(ReadHandlers[ addrTrait ])(this, alignedAddr) ;
        } // Read()
    };
}

#endif //GGADV_MMU_H

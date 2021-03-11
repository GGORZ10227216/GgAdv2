//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <optional>

#include <gg_utility.h>
#include <bit_manipulate.h>
#include <mem_enum.h>
#include <display_memory.h>
#include <gamepak_memory.h>
#include <general_memory.h>
#include <memory_exceptions.h>
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

        class MMU {
            using NS_CYCLE_VALUE = std::pair<uint8_t, uint8_t> ;
        public :
            gg_cpu::Status* cpuStatus = nullptr ;

            MMU(const std::optional<std::filesystem::path> &romPath) {
                // fixme: leave bios data to all zero for debugging
                bios_data.fill(0);
                // memcpy( bios_data.data(), biosData.data(), biosData.size() ) ;

                // fixme: open all gamepak memory area for debug only
                ROM_WS0.reserve(0x2000000) ;
                ROM_WS1.reserve(0x2000000) ;
                ROM_WS2.reserve(0x2000000) ;
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

            template <typename W, typename T>
            void Write(uint32_t addr, T value) requires std::is_same_v<W, T>
            {
                try {
                    _addrBus = addr ;
                    _dataBus = value ;
                    reinterpret_cast<W&> (_Access<WRITE, W>()) = value;
                } catch (InvalidAccessException& e) {
                    std::cout << e.what() << std::endl ;
                }
            } // Write()

            template <typename W>
            W Read(uint32_t addr)
            {
                try {
                    _addrBus = addr ;
                    return reinterpret_cast<W&> (_Access<READ, W>()) ;
                } catch (InvalidAccessException& e) {
                    if (e._addr <= 0x3fff) {
                        return bios_readBuf ;
                    } // if
                    else {
                        if (cpuStatus->GetCpuMode() == gg_cpu::E_CpuMode::ARM) {
                            return cpuStatus->fetchedBuffer[ cpuStatus->fetchIdx ] ;
                        } // if
                        else {
                            // todo: handle invalid access for THUMB mode.
                        } // else
                    } // else
                }

                return 0 ;
            } // Write()

        private :
            template<E_AccessType AT, typename W>
            uint8_t &_Access() {
                uint32_t addrAligned = _addrBus;
                addrAligned = AlignAddr<W>(addrAligned);

                unsigned addrTrait = (addrAligned & 0x0f000000) >> 24;
                uint32_t relativeAddr = addrAligned & ~(0x0f000000);

                switch (addrTrait) {
                    case 0x0:
                        if (relativeAddr < bios_data.size()) {
                            _cycleCounter = BIOS_ACCESS_CYCLE();
                            if (cpuStatus->_regs[ gg_cpu::pc ] <= 0x3fff) {
                                bios_readBuf = bios_data[addrAligned] ;
                                return bios_data[addrAligned];
                            } // if
                        } // if
                        break;
                    case 0x2:
                        if (relativeAddr < WRAM_Onboard.size()) {
                            _cycleCounter = OWRAM_ACCESS_CYCLE<W>();
                            return WRAM_Onboard[relativeAddr];
                        } // if
                        break;
                    case 0x3:
                        _cycleCounter = IWRAM_ACCESS_CYCLE();
                        if (relativeAddr < WRAM_Onchip.size())
                            return WRAM_Onchip[relativeAddr];
                        else if ((relativeAddr >> 8) == 0x03ffff00)
                            return WRAM_Onchip[relativeAddr - 0x8000]; // mirrored
                        break;
                    case 0x4:
                        _cycleCounter = IO_ACCESS_CYCLE();
                        if (relativeAddr <= IOReg.size()) {
                            if constexpr (AT == WRITE) {
                                if (addrAligned == ) {

                                } // if
                            } // if
                            return IOReg[relativeAddr];
                        } // if
                        break;
                    case 0x5:
                        if (relativeAddr <= palette.size()) {
                            _cycleCounter = PALETTE_ACCESS_CYCLE<W>();
                            return palette[relativeAddr];
                        } // if
                        break;
                    case 0x6:
                        if (relativeAddr <= VRAM.size()) {
                            _cycleCounter = VRAM_ACCESS_CYCLE<W>();
                            return VRAM[relativeAddr];
                        } // if
                        break;
                    case 0x7:
                        if (relativeAddr <= OAM.size()) {
                            _cycleCounter = OAM_ACCESS_CYCLE();
                            return OAM[relativeAddr];
                        } // if
                        break;
                    case 0x8:
                    case 0x9:
                        if (relativeAddr < ROM_BLOCK_SIZE) {
                            _cycleCounter = GAMEPAK_ACCESS_CYCLE<W, E_WS0>();
                            return ROM_WS0[relativeAddr];
                        } // if
                        break;
                    case 0xA:
                    case 0xB:
                        if (relativeAddr < ROM_BLOCK_SIZE) {
                            _cycleCounter = GAMEPAK_ACCESS_CYCLE<W, E_WS1>();
                            return ROM_WS1[relativeAddr];
                        } // if
                        break;
                    case 0xC:
                    case 0xD:
                        if (relativeAddr < ROM_BLOCK_SIZE) {
                            _cycleCounter = GAMEPAK_ACCESS_CYCLE<W, E_WS2>();
                            return ROM_WS2[relativeAddr];
                        } // if
                        break;
                    case 0xE:
                        if constexpr (SameSize<W, BYTE>()) {
                            if (relativeAddr < SRAM.size()) {
                                _cycleCounter = GAMEPAK_ACCESS_CYCLE<W, E_SRAM>() ;
                                return SRAM[relativeAddr];
                            } // if
                        } // if
                        break;
                } // switch()

                if constexpr (AT == READ)
                    throw InvalidAccessException(sizeof(W), _addrBus);
                else
                    throw InvalidAccessException(sizeof(W), _addrBus, _dataBus);
            } // Access()

            unsigned _cycleCounter = 0;

            std::array<uint8_t, 0x4000> bios_data{};
            std::array<uint8_t, 0x40000> WRAM_Onboard{};
            std::array<uint8_t, 0x8000> WRAM_Onchip{};
            gg_io::IO io ;

            std::array<uint8_t, 0x400> palette{};
            std::array<uint8_t, 0x18000> VRAM{};
            std::array<uint8_t, 0x400> OAM{};

            std::vector<uint8_t> ROM_WS0, ROM_WS1, ROM_WS2;
            std::array<uint8_t, 0x10000> SRAM;
            
            uint32_t _dataBus = 0 ;
            uint32_t _addrBus = 0 ;

            uint32_t bios_readBuf = 0 ;
            uint32_t dummy ;

            std::array<NS_CYCLE_VALUE, 4> CurrentWaitStates {
                    NS_CYCLE_VALUE(N_CYCLE_TABLE[ 0 ], S_CYCLE_TABLE[0]), // WS0
                    NS_CYCLE_VALUE(N_CYCLE_TABLE[ 0 ], S_CYCLE_TABLE[2]), // WS1
                    NS_CYCLE_VALUE(N_CYCLE_TABLE[ 0 ], S_CYCLE_TABLE[4]), // WS2
                    NS_CYCLE_VALUE(N_CYCLE_TABLE[ 0 ], 0) // SRAM(doesn't have S cycle)
            };

            template <typename W, E_GamePakRegion R>
            inline unsigned GAMEPAK_ACCESS_CYCLE() {
                const uint8_t& N_WaitState = CurrentWaitStates[ R ].first ;
                const uint8_t& S_WaitState = CurrentWaitStates[ R ].second ;

                if constexpr (SameSize<W, DWORD>())
                    return (1 + N_WaitState) + (1 + S_WaitState);
                else
                    return (1 + N_WaitState);
            } // ROM_ACCESS_CYCLE()
        };
    }

#endif //GGADV_MMU_H

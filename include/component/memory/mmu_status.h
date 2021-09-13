//
// Created by buildmachine on 2021-03-15.
//

#include <array>
#include <cstdint>

#include <cartridge.h>
#include <display_memory.h>

#ifndef GGTEST_MMU_STATUS_H
#define GGTEST_MMU_STATUS_H

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

    struct MMU_Status {
        using NS_CYCLE_VALUE = std::pair<uint8_t, uint8_t>;

        unsigned _cycleCounter = 0;

        std::array<uint8_t, 0x4000> bios_data{};
        std::array<uint8_t, 0x40000> EWRAM{};
        std::array<uint8_t, 0x8000> IWRAM{};
        std::array<uint8_t, 0x400> IOReg{};

        Cartridge cartridge ;
        VideoRAM videoRAM ;

        std::array<NS_CYCLE_VALUE, 4> CurrentWaitStates{
                NS_CYCLE_VALUE(N_CYCLE_TABLE[0], S_CYCLE_TABLE[0]), // WS0
                NS_CYCLE_VALUE(N_CYCLE_TABLE[0], S_CYCLE_TABLE[2]), // WS1
                NS_CYCLE_VALUE(N_CYCLE_TABLE[0], S_CYCLE_TABLE[4]), // WS2
                NS_CYCLE_VALUE(N_CYCLE_TABLE[0], 0) // SRAM(doesn't have S cycle)
        };

        uint32_t _dataBus = 0 ;
        uint32_t _addrBus = 0 ;

        uint32_t bios_readBuf = 0 ;
        uint32_t dummy = 0 ;

        gg_cpu::CPU_Status * _cpuStatus = nullptr;

        MMU_Status(const std::optional<std::filesystem::path> &romPath, sinkType& sink) :
            cartridge(_cycleCounter, sink),
            logger(std::make_shared<spdlog::logger>("MMU", sink))
        {
            if (romPath.has_value())
                cartridge.LoadRom(romPath.value().c_str()) ;
            else {
                logger->warn("Emulator is working under DEBUG mode(no ROM loaded!!)") ;
            } // else

        }

        [[nodiscard]] uint32_t IllegalReadValue() {
            using namespace gg_cpu ;

            if (_cpuStatus->GetCpuMode() == gg_cpu::E_CpuMode::ARM)
                return _cpuStatus->fetchedBuffer[_cpuStatus->fetchIdx];
            else {
                const uint32_t CPU_PC = _cpuStatus->_regs[ pc ] ;
                enum { BIOS_AREA = 0, IRAM_AREA = 3, OAM_AREA = 7 } ;

                uint32_t result = _cpuStatus->fetchedBuffer[_cpuStatus->fetchIdx] ;
                const uint32_t lastFetch = _cpuStatus->fetchedBuffer[!_cpuStatus->fetchIdx] ;
                const unsigned addrTrait = CPU_PC >> 24 ;

                switch (addrTrait) {
                    case BIOS_AREA:
                    case OAM_AREA:
                        // Wait, Wat? [PC + 6] is outside the pipeline!!
                        // using PC + 4 for now, just like mgba does.
                        result = (result << 16) | lastFetch;
                        break;
                    case IRAM_AREA:
                        if (CPU_PC & 2)
                            result = (result << 16) | lastFetch ;
                        else
                            result = (lastFetch << 16) | result ;
                        break;
                    default:
                            result = (result << 16) | result ;
                } // switch()

                return result ;
            } // else
        } // IllegalReadValue()

//        void IllegalWriteBehavior(E_ErrorType errType) {
//            switch (errType) {
//                case SRAM_WIDTH_MISMATCH:
//                    Unimplemented("SRAM 16/32bit access");
//                    break;
//                default:
//                    std::cerr << "Unknown memory runtime error!!" << std::endl;
//                    exit(-1);
//            } // switch
//        } // IllegalReadBehavior()

        void UpdateWaitState() {
            const uint16_t WAITCNT = IOReg[ 0x204 ] ;

            // wc == wait_control
            const unsigned wc_sram = WAITCNT & 0b11;
            CurrentWaitStates[ E_SRAM ].first = N_CYCLE_TABLE[ wc_sram ] ;

            const unsigned wc_ws0_n = (WAITCNT & 0b1100) >> 2;
            const unsigned wc_ws0_s = TestBit(WAITCNT, 4);
            CurrentWaitStates[ E_WS0 ].first = N_CYCLE_TABLE[ wc_ws0_n ] ;
            CurrentWaitStates[ E_WS0 ].second = S_CYCLE_TABLE[ wc_ws0_s ] ;

            const unsigned wc_ws1_n = (WAITCNT & 0b1100000) >> 5;
            const unsigned wc_ws1_s = TestBit(WAITCNT, 7);
            CurrentWaitStates[ E_WS1 ].first = N_CYCLE_TABLE[ wc_ws1_n ] ;
            CurrentWaitStates[ E_WS1 ].second = S_CYCLE_TABLE[ wc_ws1_s + 2 ] ;

            const unsigned wc_ws2_n = (WAITCNT & 0b1100000000) >> 8;
            const unsigned wc_ws2_s = TestBit(WAITCNT, 10);
            CurrentWaitStates[ E_WS2 ].first = N_CYCLE_TABLE[ wc_ws2_n ] ;
            CurrentWaitStates[ E_WS2 ].second = S_CYCLE_TABLE[ wc_ws2_s + 4 ] ;
        } // UpdateWaitState()

        loggerType logger ;

        uint32_t lastAccessAddr = 0x0 ;
        E_AccessType requestAccessType = N_Cycle ;
    };
}

#endif //GGTEST_MMU_STATUS_H

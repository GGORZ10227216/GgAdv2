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

        Cartridge cartridge;
        VideoRAM videoRAM;

        union CycleSet {
            uint8_t cycle[3];
            uint8_t byte, word, dword;
        };
//        struct CycleSet {
//            uint8_t byte = 1, word = 1, dword = 1;
//        };


        /**
         * N - Non-sequential cycle
         *     Requests a transfer to/from an address which is NOT related to the address used in the previous cycle. (Called 1st Access in GBA language).
         *     The execution time for 1N is 1 clock cycle (plus non-sequential access waitstates).
         *
         * S - Sequential cycle
         *     Requests a transfer to/from an address which is located directly after the address used in the previous cycle. Ie. for 16bit or 32bit accesses at incrementing addresses, the first access is Non-sequential, the following accesses are sequential. (Called 2nd Access in GBA language).
         *     The execution time for 1S is 1 clock cycle (plus sequential access waitstates).
         *
         * I - Internal Cycle
         *     CPU is just too busy, not even requesting a memory transfer for now.
         *     The execution time for 1I is 1 clock cycle (without any waitstates).
         * */

        using cycleinfo = std::array<CycleSet, 15> ;

        std::array<cycleinfo, 2> memCycleTable {
            cycleinfo {
                    CycleSet{1, 1, 1}, // BIOS
                    CycleSet{1, 1, 1}, // unused#1
                    CycleSet{3, 3, 6}, // EWRAM
                    CycleSet{1, 1, 1}, // IWRAM
                    CycleSet{1, 1, 1}, // IO
                    CycleSet{1, 1, 2}, // Palette
                    CycleSet{1, 1, 2}, // VRAM
                    CycleSet{1, 1, 1}, // OAM
                    CycleSet{5, 5, 8}, // WS0_A
                    CycleSet{5, 5, 8}, // WS0_B
                    CycleSet{5, 5, 8}, // WS1_A
                    CycleSet{5, 5, 8}, // WS1_B
                    CycleSet{5, 5, 8}, // WS2_A
                    CycleSet{5, 5, 8},  // WS2_B
                    CycleSet{9, 0, 0}  // SRAM(byte access only)
            },
            cycleinfo {
                    CycleSet{1, 1, 1}, // BIOS
                    CycleSet{1, 1, 1}, // unused#1
                    CycleSet{3, 3, 6}, // EWRAM
                    CycleSet{1, 1, 1}, // IWRAM
                    CycleSet{1, 1, 1}, // IO
                    CycleSet{1, 1, 2}, // Palette
                    CycleSet{1, 1, 2}, // VRAM
                    CycleSet{1, 1, 1}, // OAM
                    CycleSet{2, 2, 4}, // WS0_A
                    CycleSet{2, 2, 4}, // WS0_B
                    CycleSet{5, 5, 10}, // WS1_A
                    CycleSet{5, 5, 10}, // WS1_B
                    CycleSet{9, 9, 18}, // WS2_A
                    CycleSet{9, 9, 18},  // WS2_B
                    CycleSet{0, 0, 0}  // SRAM(doesn't have S Cycle)
            }
        };

        uint32_t bios_readBuf = 0;

        gg_cpu::CPU_Status *_cpuStatus = nullptr;

        MMU_Status(const std::optional<std::filesystem::path> &romPath, sinkType &sink) :
                cartridge(_cycleCounter, sink),
                logger(std::make_shared<spdlog::logger>("MMU", sink)) {
            if (romPath.has_value())
                cartridge.LoadRom(romPath.value().c_str());
            else {
                logger->warn("Emulator is working under DEBUG mode(no ROM loaded!!)");
            } // else

        }

        [[nodiscard]] uint32_t IllegalReadValue() {
            using namespace gg_cpu;

            if (_cpuStatus->GetCpuMode() == gg_cpu::E_CpuMode::ARM)
                return _cpuStatus->fetchedBuffer[_cpuStatus->fetchIdx];
            else {
                const uint32_t CPU_PC = _cpuStatus->_regs[pc];
                enum {
                    BIOS_AREA = 0, IRAM_AREA = 3, OAM_AREA = 7
                };

                uint32_t result = 0;
                const uint32_t lastFetch = _cpuStatus->fetchedBuffer[!_cpuStatus->fetchIdx];
                const uint32_t thisFetch = _cpuStatus->fetchedBuffer[_cpuStatus->fetchIdx];
                const unsigned addrTrait = CPU_PC >> 24;

                switch (addrTrait) {
                    case BIOS_AREA:
                    case OAM_AREA:
                        // Wait, Wat? [PC + 6] is outside the pipeline!!
                        // using PC + 4 for now, just like mgba does.
                        result = (thisFetch << 16) | lastFetch;
                        break;
                    case IRAM_AREA:
                        if (CPU_PC & 2)
                            result = (thisFetch << 16) | lastFetch;
                        else
                            result = (lastFetch << 16) | thisFetch;
                        break;
                    default:
                        result = (thisFetch << 16) | thisFetch;
                } // switch()

                return result;
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
            enum {N = 0, S = 1};
            const uint16_t WAITCNT = IOReg[0x204];

            // wc == wait_control
            const unsigned wc_sram = WAITCNT & 0b11;

            memCycleTable[N][E_SRAM].byte = N_CYCLE_TABLE[wc_sram] + 1; // only use this

            const unsigned wc_ws0_n = (WAITCNT & 0b1100) >> 2;
            const unsigned wc_ws0_s = TestBit(WAITCNT, 4);
            memCycleTable[N][E_WS0].byte = N_CYCLE_TABLE[wc_ws0_n] + 1;
            memCycleTable[N][E_WS0].word = N_CYCLE_TABLE[wc_ws0_n] + 1;
            memCycleTable[N][E_WS0].dword = N_CYCLE_TABLE[wc_ws0_n] + 1 + S_CYCLE_TABLE[wc_ws0_s] + 1;
            memCycleTable[N][E_WS0_B] = memCycleTable[N][E_WS0];

            memCycleTable[S][E_WS0].byte = S_CYCLE_TABLE[wc_ws0_s] + 1;
            memCycleTable[S][E_WS0].word = S_CYCLE_TABLE[wc_ws0_s] + 1;
            memCycleTable[S][E_WS0].dword = (S_CYCLE_TABLE[wc_ws0_s] + 1)*2;
            memCycleTable[S][E_WS0_B] = memCycleTable[S][E_WS0];


            const unsigned wc_ws1_n = (WAITCNT & 0b1100000) >> 5;
            const unsigned wc_ws1_s = TestBit(WAITCNT, 7) + 2;
            memCycleTable[N][E_WS1].byte = N_CYCLE_TABLE[wc_ws1_n] + 1;
            memCycleTable[N][E_WS1].word = N_CYCLE_TABLE[wc_ws1_n] + 1;
            memCycleTable[N][E_WS1].dword = N_CYCLE_TABLE[wc_ws1_n] + 1 + S_CYCLE_TABLE[wc_ws1_s] + 1;
            memCycleTable[N][E_WS1_B] = memCycleTable[N][E_WS1];

            memCycleTable[S][E_WS1].byte = S_CYCLE_TABLE[wc_ws1_s] + 1;
            memCycleTable[S][E_WS1].word = S_CYCLE_TABLE[wc_ws1_s] + 1;
            memCycleTable[S][E_WS1].dword = (S_CYCLE_TABLE[wc_ws1_s] + 1)*2;
            memCycleTable[S][E_WS1_B] = memCycleTable[S][E_WS1];

            const unsigned wc_ws2_n = (WAITCNT & 0b1100000000) >> 8;
            const unsigned wc_ws2_s = TestBit(WAITCNT, 10) + 4;
            memCycleTable[N][E_WS2].byte = N_CYCLE_TABLE[wc_ws2_n] + 1;
            memCycleTable[N][E_WS2].word = N_CYCLE_TABLE[wc_ws2_n] + 1;
            memCycleTable[N][E_WS2].dword = N_CYCLE_TABLE[wc_ws2_n] + 1 + S_CYCLE_TABLE[wc_ws2_s] + 1;
            memCycleTable[N][E_WS2_B] = memCycleTable[N][E_WS2];

            memCycleTable[S][E_WS2].byte = S_CYCLE_TABLE[wc_ws2_s] + 1;
            memCycleTable[S][E_WS2].word = S_CYCLE_TABLE[wc_ws2_s] + 1;
            memCycleTable[S][E_WS2].dword = (S_CYCLE_TABLE[wc_ws2_s] + 1)*2;
            memCycleTable[S][E_WS2_B] = memCycleTable[S][E_WS2];
        } // UpdateWaitState()

        loggerType logger;
        E_AccessType requestAccessType = N_Cycle;
        uint32_t lastAccessAddr;
    };
}

#endif //GGTEST_MMU_STATUS_H

//
// Created by buildmachine on 2021-03-15.
//

#include <array>
#include <cstdint>

#include <logger.h>

#include <cartridge.h>
#include <gba_bios.h>

#ifndef GGTEST_MMU_STATUS_H
#define GGTEST_MMU_STATUS_H

namespace gg_core {
    namespace gg_mem {
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
            MMU_Status(GbaInstance& instance, const std::optional<std::filesystem::path> &romPath) ;

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

            [[nodiscard]] uint32_t IllegalReadValue() ;
            void UpdateWaitState() ;

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

            uint32_t bios_readBuf = 0;
            gg_cpu::CPU_Status& _cpuStatus;

            loggerType logger;
            E_AccessType requestAccessType = N_Cycle;
            uint32_t lastAccessAddr;
        };
    }
}

#endif //GGTEST_MMU_STATUS_H

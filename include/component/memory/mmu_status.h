//
// Created by buildmachine on 2021-03-15.
//

#include <array>
#include <cstdint>

#include <cartridge.h>

#ifndef GGTEST_MMU_STATUS_H
#define GGTEST_MMU_STATUS_H

namespace gg_core::gg_mem {
    struct MMU_Status {
        using NS_CYCLE_VALUE = std::pair<uint8_t, uint8_t>;

        unsigned _cycleCounter = 0;

        std::array<uint8_t, 0x4000> bios_data{};
        std::array<uint8_t, 0x40000> EWRAM{};
        std::array<uint8_t, 0x8000> IWRAM{};
        std::array<uint8_t, 0x400> IOReg{};

        std::array<uint8_t, 0x400> palette{};
        std::array<uint8_t, 0x18000> VRAM{};
        std::array<uint8_t, 0x400> OAM{};

        std::vector<uint8_t> ROM_WS0, ROM_WS1, ROM_WS2;
        Cartridge cartridge ;

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

        gg_cpu::CPU_Status *const _cpuStatus = nullptr;

        MMU_Status(const char* romPath) :
            cartridge(romPath)
        {

        }

        [[nodiscard]] uint32_t IllegalReadValue() {
            if (_cpuStatus->GetCpuMode() == gg_cpu::E_CpuMode::ARM)
                return _cpuStatus->fetchedBuffer[_cpuStatus->fetchIdx];
            else
                Unimplemented("thumb invalid memory access");
        } // IllegalReadValue()

        void IllegalWriteBehavior(E_ErrorType errType) {
            switch (errType) {
                case SRAM_WIDTH_MISMATCH:
                    Unimplemented("SRAM 16/32bit access");
                    break;
                default:
                    std::cerr << "Unknown memory runtime error!!" << std::endl;
                    exit(-1);
            } // switch
        } // IllegalReadBehavior()

        void UpdateWaitState() {
            const uint16_t WAITCNT = IOReg[ 0x204 ] ;
            // todo
        } // UpdateWaitState()
    };
}

#endif //GGTEST_MMU_STATUS_H

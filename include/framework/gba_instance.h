//
// Created by orzgg on 2020-09-04.
//

#include <thread>
#include <optional>
#include <filesystem>
#include <iostream>

#include <status.h>
#include <mmu.h>
#include <io.h>
#include <arm_decoder.h>

#ifndef GGADV_GBA_INSTANCE_H
#define GGADV_GBA_INSTANCE_H

namespace gg_core {
    class GbaInstance final {
    public :
        gg_cpu::Status _status;
        gg_mem::MMU _mem;
        gg_io::IOReg _io;

        GbaInstance(const std::optional<std::filesystem::path> &romPath) :
                _mem(romPath), _io() {
            // _worker = std::thread(&GbaInstance::Run, this);
            // Run() ;
        } // GbaInstance()

        void Run() {
            _isRunning = true ;

            RefillPipeline();
            Fetch() ;

            while (_isRunning) {
                CPUTick();
            } // while
        } // Run()

        ~GbaInstance() {
            if (_worker.joinable())
                _worker.join();
        } // ~GbaInstance()

        bool _isRunning;
        std::thread _worker;

        void CPUTick() {
            uint32_t i = _status.CurrentInstruction() ;
            uint32_t hash = ((i & 0x0ff00000) >> 16) | ((i & 0xf0) >> 4) ;

            gg_cpu::armHandlers[ hash ](*this) ;
            Fetch() ;
        } // Tick()

        void CPUTick_Debug(uint32_t inst) {
            _status.fetchedBuffer[ _status.pipelineCnt ] = inst ;
            uint32_t hash = ((inst & 0x0ff00000) >> 16) | ((inst & 0xf0) >> 4) ;

            gg_cpu::armHandlers[ hash ](*this) ;
            // Execute only ONE instruction, no need to fetch()!!
        } // Tick()

        void RefillPipeline() {
            using namespace gg_cpu;
            unsigned pcOffset = _status.GetCpuMode() == ARM ? 4 : 2;
            unsigned pcBase ;

            if (_status.GetCpuMode() == ARM) {
                pcBase = (_status._regs[pc] & ~0x3) ;
                _status.fetchedBuffer[0] = _mem.Read32(pcBase);
                _status.fetchedBuffer[1] = _mem.Read32(pcBase + pcOffset);
            } // if
            else {
                pcBase = (_status._regs[pc] & ~0x1) ;
                _status.fetchedBuffer[0] = _mem.Read16(pcBase);
                _status.fetchedBuffer[1] = _mem.Read16(pcBase + pcOffset);
            } // else

            _status._regs[pc] = pcBase + 2*pcOffset;
            _status.pipelineCnt = 0;
        } // RefillPipeline()

        void Fetch() {
            using namespace gg_cpu;
            unsigned pcOffset = _status.GetCpuMode() == ARM ? 4 : 2;

            _status.pipelineCnt = (_status.pipelineCnt + 1) % _status.fetchedBuffer.size();
            if (_status.GetCpuMode() == ARM)
                _status.fetchedBuffer[_status.pipelineCnt] = _mem.Read32(_status._regs[pc]);
            else
                _status.fetchedBuffer[_status.pipelineCnt] = _mem.Read16(_status._regs[pc]);
            _status._regs[pc] += pcOffset;
        } // Fetch()

    private:
        bool pipelineFilled = false ;
        int testCnt = 2048 ;
    };
}

#define CURRENT_INSTRUCTION instance._status.CurrentInstruction()
#define CPU_REG instance._status._regs

#include <v4_alu_implement.h>
#include <v4_multiply_implement.h>
#include <v4_mem_implement.h>
#include <v4_irq_implement.h>
#include <v4_psr_implement.h>
#include <v4_branch_implement.h>

#endif //GGADV_GBA_INSTANCE_H

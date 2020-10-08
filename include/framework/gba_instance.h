//
// Created by orzgg on 2020-09-04.
//

#include <thread>
#include <optional>
#include <filesystem>

#include <arm_instruction_table.h>
#include <status.h>
#include <mmu.h>
#include <io.h>
#include <iostream>

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
            RefillPipeline();
            // _worker = std::thread(&GbaInstance::Run, this);
            Run() ;
        } // GbaInstance()

        void Run() {
            _isRunning = true ;
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

            if (!pipelineFilled)
                Fetch() ;
            else
                pipelineFilled = false ;

            if (testCnt == 0) {
                _isRunning = false ;
                return ;
            } // if
            else
                testCnt = testCnt - 1 ;
        } // Tick()

        void RefillPipeline() {
            using namespace gg_cpu;
            unsigned pcOffset = _status.GetCpuMode() == ARM ? 4 : 2;
            unsigned pcBase = 0;

            for (int i = 0; i < _status.fetchedBuffer.size(); ++i) {
                pcBase = _status._regs[pc] + pcOffset * i;
                if (pcOffset == 4)
                    _status.fetchedBuffer[i] = _mem.Read32(pcBase);
                else
                    _status.fetchedBuffer[i] = _mem.Read16(pcBase);
            } // for

            _status._regs[pc] = pcBase;
            _status.pipelineCnt = 0;
            pipelineFilled = true ;
        } // RefillPipeline()

        void Fetch() {
            using namespace gg_cpu;
            unsigned pcOffset = _status.GetCpuMode() == ARM ? 4 : 2;

            _status._regs[pc] += pcOffset;
            if (pcOffset == 4)
                _status.fetchedBuffer[_status.pipelineCnt] = _mem.Read32(_status._regs[pc]);
            else
                _status.fetchedBuffer[_status.pipelineCnt] = _mem.Read16(_status._regs[pc]);
            _status.pipelineCnt = (_status.pipelineCnt + 1) % _status.fetchedBuffer.size();
        } // Fetch()

    private:
        bool pipelineFilled = false ;
        int testCnt = 1024 ;
    };
}

#define CURRENT_INSTRUCTION instance._status.CurrentInstruction()
#define CPU_REG instance._status._regs

#include <v4_alu_implement.h>
#include <v4_branch_implement.h>
#include <v4_block_transfer_implement.h>
#include <v4_interrupt_implement.h>
#include <v4_mul_implement.h>
#include <v4_mull_implement.h>
#include <v4_psr_implement.h>
#include <v4_swap_implement.h>
#include <v4_transfer_implement.h>
#include <v4_half_transfer_implement.h>

#endif //GGADV_GBA_INSTANCE_H

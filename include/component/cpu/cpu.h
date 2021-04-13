//
// Created by orzgg on 2020-09-04.
//

#include <thread>
#include <optional>
#include <filesystem>
#include <iostream>

#include <arm_decoder.h>
#include <cpu_status.h>
#include <mmu.h>
#include <io.h>

#ifndef GGADV_GBA_INSTANCE_H
#define GGADV_GBA_INSTANCE_H

namespace gg_core::gg_cpu {
    class CPU final : public CPU_Status {
    public :
        gg_core::gg_mem::MMU &_mem;

        CPU(gg_mem::MMU &instanceMemory) :
            _mem(instanceMemory)
        {
            _mem._cpuStatus = this ;
            fetchedBuffer[0] = _mem.Read32(0);
            fetchedBuffer[1] = _mem.Read32(4);
            _regs[pc] = 8;
            fetchIdx = 1;
        } // CPU()

        void CPUTick() {
            currentInstruction = fetchedBuffer[ !fetchIdx ] ;
            std::invoke(Fetch, this) ;
            instructionTable[ iHash(currentInstruction) ](*this) ;
        } // Tick()

        void CPU_Test(uint32_t inst) {
//            try {
                currentInstruction = inst ;
                instructionTable[ iHash(currentInstruction) ](*this) ;
//            } catch (gg_mem::MMU::InvalidAccessException& e) {
//                std::cout << e.what() << std::endl ;
//                // exit(-1) ;
//            } // try-catch()
        } // Tick()

        void RefillPipeline() {
            std::invoke(RefillPipelineHandler, this) ;
        }

        void ChangeCpuMode(E_CpuMode mode) {
            if (mode == THUMB) {
                _cpsr |= 0x1 << T ;
                RefillPipelineHandler = &CPU::THUMB_RefillPipeline ;
            } // if
            else {
                _cpsr &= ~(0x1 << T);
                RefillPipelineHandler = &CPU::ARM_RefillPipeline ;
            } // else
        } // ChangeCpuMode()

    private:
        bool pipelineFilled = false ;
        int testCnt = 2048 ;

        void (CPU::*RefillPipelineHandler)() = &CPU::ARM_RefillPipeline ;

        void ARM_RefillPipeline() {
            using namespace gg_cpu;

            unsigned pcBase = (_regs[pc] & ~0x3) ;
            fetchedBuffer[0] = _mem.Read32(pcBase);
            fetchedBuffer[1] = _mem.Read32(pcBase + 4);

            _regs[pc] = pcBase + 4;
            fetchIdx = 1;
        } // RefillPipeline()

        void THUMB_RefillPipeline() {
            using namespace gg_cpu;

            unsigned pcBase = (_regs[pc] & ~0x1) ;
            fetchedBuffer[0] = _mem.Read16(pcBase);
            fetchedBuffer[1] = _mem.Read16(pcBase + 2);

            _regs[pc] = pcBase + 2;
            fetchIdx = 1;
        } // RefillPipeline()

        void ARM_Fetch() {
            _regs[gg_cpu::pc] += 4;
            fetchIdx = !fetchIdx;
            fetchedBuffer[fetchIdx] = _mem.Read32(_regs[gg_cpu::pc]);
        } // ARM_Fetch()

        void THUMB_Fetch() {
            _regs[gg_cpu::pc] += 2;
            fetchIdx = (fetchIdx + 1) % fetchedBuffer.size();
            fetchedBuffer[fetchIdx] = _mem.Read16(_regs[gg_cpu::pc]);
        } // THUMB_Fetch()
        
        static inline auto ARM_instructionHashFunc = [](uint32_t inst) {
            return ((inst & 0x0ff00000) >> 16) | ((inst & 0xf0) >> 4) ;
        };

        static inline auto THUMB_instructionHashFunc = [](uint32_t inst) {
            // todo: thumb hash function
            return 0 ;
        };

        uint32_t (*iHash)(uint32_t) = ARM_instructionHashFunc ;
        void (CPU::*Fetch)() = &CPU::ARM_Fetch ;
        HandlerType const*  instructionTable = ARM_HandlerTable.data() ;
    };
}

#define CURRENT_INSTRUCTION instance.CurrentInstruction()
#define CPU_REG instance._regs

#include <v4_alu_implement.h>
#include <v4_multiply_implement.h>
#include <v4_mem_implement.h>
#include <v4_irq_implement.h>
#include <v4_psr_implement.h>
#include <v4_branch_implement.h>

#endif //GGADV_GBA_INSTANCE_H

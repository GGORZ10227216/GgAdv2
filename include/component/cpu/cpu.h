//
// Created by orzgg on 2020-09-04.
//

#include <thread>
#include <optional>
#include <filesystem>
#include <iostream>

#include <decoder.h>

#ifndef GGADV_CPU_H
#define GGADV_CPU_H

namespace gg_core::gg_cpu {
    using CycleType = gg_mem::E_AccessType ;

    class CPU final : public CPU_Status {
    public :
        gg_core::gg_mem::MMU &_mem;

        CPU(gg_mem::MMU &instanceMemory, sinkType& sink) :
            _mem(instanceMemory),
            logger(std::make_shared<spdlog::logger>("CPU", sink))
        {
            // fetchIdx point to pc+4
            // !fetchIdx point to pc

            _mem._cpuStatus = this ;
            fetchedBuffer[0] = _mem.Read<uint32_t>(0, gg_mem::N_Cycle);
            fetchedBuffer[1] = _mem.Read<uint32_t>(4, gg_mem::S_Cycle);
            _regs[pc] = 4;
            fetchIdx = 1;
        } // CPU()

        void CPUTick() {
            currentInstruction = fetchedBuffer[ !fetchIdx ] ;
            // Fixme: Should I_Cycle move fetch into instruction handler?
//            std::invoke(Fetch, this) ;
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

        void ChangeCpuMode(E_CpuMode mode) {
            if (mode == THUMB) {
                _cpsr |= 0x1 << T ;
                RefillPipeline = &CPU::THUMB_RefillPipeline ;
            } // if
            else {
                _cpsr &= ~(0x1 << T);
                RefillPipeline = &CPU::ARM_RefillPipeline ;
            } // else
        } // ChangeCpuMode()

        loggerType logger ;

        static void ARM_RefillPipeline(CPU* self, CycleType first, CycleType second) {
            using namespace gg_cpu;

            unsigned pcBase = (self->_regs[pc] & ~0x3) ;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase, first);
            self->fetchedBuffer[self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase + 4, second);

            self->_regs[pc] = pcBase + 4;
        } // RefillPipeline()

        static void THUMB_RefillPipeline(CPU* self, CycleType first, CycleType second) {
            using namespace gg_cpu;

            unsigned pcBase = (self->_regs[pc] & ~0x1) ;
            self->fetchedBuffer[0] = self->_mem.Read<uint16_t>(pcBase, first);
            self->fetchedBuffer[1] = self->_mem.Read<uint16_t>(pcBase + 2, second);

            self->_regs[pc] = pcBase + 2;
            self->fetchIdx = 1;
        } // RefillPipeline()

        static void ARM_Fetch(CPU* self, gg_mem::E_AccessType accessType) {
            self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 4) & ~0x3;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(self->_regs[gg_cpu::pc], accessType);
            self->fetchIdx = !self->fetchIdx;
        } // ARM_Fetch()

        static void THUMB_Fetch(CPU* self, gg_mem::E_AccessType accessType) {
            self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 2) & ~0x1;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint16_t>(self->_regs[gg_cpu::pc], accessType);
            self->fetchIdx = !self->fetchIdx;
        } // THUMB_Fetch()
        
        static inline auto ARM_instructionHashFunc = [](uint32_t inst) {
            return ((inst & 0x0ff00000) >> 16) | ((inst & 0xf0) >> 4) ;
        };

        static inline auto THUMB_instructionHashFunc = [](uint32_t inst) {
            // todo: thumb hash function
            return 0 ;
        };

        uint32_t (*iHash)(uint32_t) = ARM_instructionHashFunc ;
        void (*Fetch)(CPU*, gg_mem::E_AccessType) = &CPU::ARM_Fetch ;
        void (*RefillPipeline)(CPU*, CycleType, CycleType) = &CPU::ARM_RefillPipeline ;
        HandlerType const*  instructionTable = ARM_HandlerTable.data() ;
    };
}

#define CURRENT_INSTRUCTION instance.CurrentInstruction()
#define CPU_REG instance._regs

// ARM implementation
#include <v4_alu_implement.h>
#include <v4_multiply_implement.h>
#include <v4_mem_implement.h>
#include <v4_irq_implement.h>
#include <v4_psr_implement.h>
#include <v4_branch_implement.h>

// Thumb implementation
#include <v4t_format1.h>
#include <v4t_format2.h>
#include <v4t_format3.h>
#include <v4t_format4.h>
#include <v4t_format5.h>
#include <v4t_format6.h>
#endif //GGADV_CPU_H

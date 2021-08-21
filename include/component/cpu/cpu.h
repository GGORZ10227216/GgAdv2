//
// Created by orzgg on 2020-09-04.
//

#include <thread>
#include <optional>
#include <filesystem>
#include <iostream>

#include <decoder.h>
#include <arm_asm.h>

#ifndef GGADV_CPU_H
#define GGADV_CPU_H

namespace gg_core::gg_cpu {
    using CycleType = gg_mem::E_AccessType ;

    class CPU final : public CPU_Status {
    public :
        gg_core::gg_mem::MMU &_mem;

        ArmAssembler armAsm ;
        ArmAssembler thumbAsm ;

        CPU(gg_mem::MMU &instanceMemory, sinkType& sink) :
            _mem(instanceMemory),
            logger(std::make_shared<spdlog::logger>("CPU", sink)),
            armAsm(ASMMODE::ARM),
            thumbAsm(ASMMODE::THUMB)
        {
            /**
            ** fetchIdx point to pc+4
            ** !fetchIdx point to pc
            ** fetchidx always point to last fetched instruction
            **/

            _mem._cpuStatus = this ;
            fetchedBuffer[0] = _mem.Read<uint32_t>(0, gg_mem::N_Cycle);
            fetchedBuffer[1] = _mem.Read<uint32_t>(4, gg_mem::S_Cycle);

            _regs[r0] = 0xca5 ;

            _regs[pc] = 4;
            fetchIdx = 1;
        } // CPU()

        void CPUTick() {
            currentInstruction = fetchedBuffer[ !fetchIdx ] ;

            unsigned condition = (currentInstruction & 0xf0000000) >> 28 ;
            auto checker = conditionChecker[ condition ] ;

            if ((this->*checker)())
                instructionTable[ iHash(currentInstruction) ](*this) ;
            else
                Fetch(this, gg_mem::S_Cycle);
        } // Tick()

        void CPU_DebugTick() {
            currentInstruction = fetchedBuffer[ !fetchIdx ] ;
            std::string mode, instr, psr, info ;

            auto OpMode2Str = [](unsigned mCode) {
                switch (mCode) {
                    case USR:
                        return "USR" ;
                    case IRQ:
                        return "IRQ" ;
                    case ABT:
                        return "ABT" ;
                    case UND:
                        return "UND" ;
                    case FIQ:
                        return "FIQ" ;
                    case SVC:
                        return "SVC" ;
                    case SYS:
                        return "SYS" ;
                } // switch

                return "ERROR" ;
            };

            psr = fmt::format("\tcpsr: {:>#010x} spsr: ",
                ReadCPSR()
            ) ;

            if (GetOperationMode() == USR || GetOperationMode() == SYS)
                psr += "No Value" ;
            else
                psr += fmt::format("{:>#010x}", ReadSPSR()) ;

            info = fmt::format(reg4InfoStr,
                _regs[r0] , _regs[r1], _regs[r2], _regs[r3],
                _regs[r4] , _regs[r5], _regs[r6], _regs[r7],
                _regs[r8] , _regs[r9], _regs[r10], _regs[r11],
                _regs[r12] , _regs[sp], _regs[lr], _regs[pc] + instructionLength
            ) ;

            if (GetCpuMode() == E_CpuMode::ARM) {
                mode = fmt::format("\tCPUMode: ARM, OpMode: {}", OpMode2Str(GetOperationMode())) ;
                instr = fmt::format("[{:#x}] {}", lastPC, armAsm.DASM(currentInstruction)) ;
            } // if
            else {
                mode = fmt::format("\tCPUMode: THUMB, OpMode: {}", OpMode2Str(GetOperationMode())) ;
                instr = fmt::format("[{:#x}] {}", lastPC, thumbAsm.DASM(currentInstruction)) ;
            } // else


            std::cout << instr << std::endl ;
            std::cout << mode << std::endl ;
            std::cout << psr << std::endl ;
            std::cout << info << std::endl ;


            unsigned condition = 0x0;
            if (GetCpuMode() == E_CpuMode::ARM)
                condition = (currentInstruction & 0xf0000000) >> 28 ;
            else
                condition = E_CondName::AL ;

            auto checker = conditionChecker[ condition ] ;

            if ((this->*checker)())
                instructionTable[ iHash(currentInstruction) ](*this) ;
            else
                Fetch(this, gg_mem::S_Cycle);
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
                Fetch = &CPU::THUMB_Fetch ;
                iHash = THUMB_instructionHashFunc ;
                instructionTable = Thumb_HandlerTable.data() ;
                instructionLength = 2 ;
            } // if
            else {
                _cpsr &= ~(0x1 << T);
                RefillPipeline = &CPU::ARM_RefillPipeline ;
                Fetch = &CPU::ARM_Fetch ;
                iHash = ARM_instructionHashFunc ;
                instructionTable = ARM_HandlerTable.data() ;
                instructionLength = 4 ;
            } // else
        } // ChangeCpuMode()

        void ChangeOperationMode(E_OperationMode newMode) {
            uint32_t oldStatus = _cpsr & ~0x1f ;
            WriteCPSR(oldStatus | newMode) ;
        }

        template <typename T>
        void AccessUsrRegBankInPrivilege(T Action) {
            uint32_t originalOpMode = _cpsr & 0x1f ;
            ChangeOperationMode(USR) ;
            Action() ;
            ChangeOperationMode(static_cast<E_OperationMode>(originalOpMode)) ;
        }

        loggerType logger ;

        static void ARM_RefillPipeline(CPU* self, CycleType first, CycleType second) {
            using namespace gg_cpu;

            unsigned pcBase = (self->_regs[pc] & ~0x3) ;

            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase, first);
            self->fetchedBuffer[self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase + 4, second);

            self->lastPC = pcBase ;
            self->_regs[pc] = pcBase + 4;
        } // RefillPipeline()

        static void THUMB_RefillPipeline(CPU* self, CycleType first, CycleType second) {
            // todo: thumb pipeline alignment mechanism for invalid access.
            using namespace gg_cpu;

            unsigned pcBase = (self->_regs[pc] & ~0x1) ;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint16_t>(pcBase, first);
            self->fetchedBuffer[self->fetchIdx] = self->_mem.Read<uint16_t>(pcBase + 2, second);

            self->lastPC = pcBase ;
            self->_regs[pc] = pcBase + 2;
        } // RefillPipeline()

        static void ARM_Fetch(CPU* self, gg_mem::E_AccessType accessType) {
            self->lastPC = self->_regs[gg_cpu::pc] ;
            self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 4) & ~0x3;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(self->_regs[gg_cpu::pc], accessType);
            self->fetchIdx = !self->fetchIdx;
        } // ARM_Fetch()

        static void THUMB_Fetch(CPU* self, gg_mem::E_AccessType accessType) {
            self->lastPC = self->_regs[gg_cpu::pc] ;
            self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 2) & ~0x1;
            self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint16_t>(self->_regs[gg_cpu::pc], accessType);
            self->fetchIdx = !self->fetchIdx;
        } // THUMB_Fetch()
        
        static inline auto ARM_instructionHashFunc = [](uint32_t inst) {
            return ((inst & 0x0ff00000) >> 16) | ((inst & 0xf0) >> 4) ;
        };

        static inline auto THUMB_instructionHashFunc = [](uint32_t inst) {
            // todo: thumb hash function
            return (inst & 0xffff) >> 6 ;
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
#include <v4t_format7.h>
#include <v4t_format8.h>
#include <v4t_format9.h>
#include <v4t_format10.h>
#include <v4t_format11.h>
#include <v4t_format12.h>
#include <v4t_format13.h>
#include <v4t_format14.h>
#include <v4t_format15.h>
#include <v4t_format16.h>
#include <v4t_format17.h>
#include <v4t_format18.h>
#include <v4t_format19.h>
#endif //GGADV_CPU_H

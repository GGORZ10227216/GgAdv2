//
// Created by orzgg on 2020-09-04.
//

#include <arm_asm.h>

#include <logger.h>
#include <cpu_enum.h>
#include <cpu_status.h>

#ifndef GGADV_CPU_H
#define GGADV_CPU_H

namespace gg_core {
    class GbaInstance ;
    namespace gg_mem {
        class MMU ;
    }

    namespace gg_cpu {
        class CPU final : public CPU_Status {
        public :
            GbaInstance& _instance ;
            gg_mem::MMU& _mem ;

            ArmAssembler armAsm ;
            ArmAssembler thumbAsm ;
            loggerType logger ;

            CPU(GbaInstance& instanceMemory, sinkType& sink) ;

            void SetF() { _cpsr |= (1 << 6); } // SetF()
            void ClearF() { _cpsr &= ~(1 << 6); } // ClearF()
            void SetI() { _cpsr |= (1 << 7); CPU_StateChange(); } // SetI()
            void ClearI() { _cpsr &= ~(1 << 7); CPU_StateChange(); } // ClearI()
            void SetV() { _cpsr |= (1 << 28); } // SetV()
            void ClearV() { _cpsr &= ~(1 << 28); } // ClearV()
            void SetC() { _cpsr |= (1 << 29); } // SetC()
            void ClearC() { _cpsr &= ~(1 << 29); } // ClearC()
            void SetZ() { _cpsr |= (1 << 30); } // SetZ()
            void ClearZ() { _cpsr &= ~(1 << 30); } // ClearZ()
            void SetN() { _cpsr |= (1 << 31); } // SetN()
            void ClearN() { _cpsr &= ~(1 << 31); } // ClearN()

            void CPU_DebugTick() ;
            void CPU_Test(uint32_t inst) ;
            void ChangeCpuMode(E_CpuMode mode) ;
            void ChangeOperationMode(E_OperationMode newMode) ;

            void CPU_StateChange() ;
            void RaiseInterrupt(IRQ_TYPE irqType) ;

            template <typename T>
            void AccessUsrRegBankInPrivilege(T Action) {
                uint32_t originalOpMode = _cpsr & 0x1f ;
                ChangeOperationMode(USR) ;
                Action() ;
                ChangeOperationMode(static_cast<E_OperationMode>(originalOpMode)) ;
            } // AccessUsrRegBankInPrivilege()

            // todo: Maybe fetch and refill in both ARM and Thumb mode are 32bit access
            //       this hypothesis can explain why illegal access need [PC + 6]
            //       But I'm not sure about cycle correctness, need more test.

            static void ARM_RefillPipeline(CPU* self, gg_mem::CycleType first, gg_mem::CycleType second) ;
            static void THUMB_RefillPipeline(CPU* self, gg_mem::CycleType first, gg_mem::CycleType second) ;

            static void ARM_Fetch(CPU* self, gg_mem::E_AccessType accessType) ;
            static void THUMB_Fetch(CPU* self, gg_mem::E_AccessType accessType) ;

            void WriteCPSR(uint32_t newCPSR) ;
            void WriteSPSR(uint32_t value) ;

            static inline auto ARM_instructionHashFunc = [](uint32_t inst) {
                return ((inst & 0x0ff00000) >> 16) | ((inst & 0xf0) >> 4) ;
            };

            static inline auto THUMB_instructionHashFunc = [](uint32_t inst) {
                // todo: thumb hash function
                return (inst & 0xffff) >> 6 ;
            };
        };
    }
}

#define CURRENT_INSTRUCTION instance.CurrentInstruction()
#define CPU_REG instance._regs

#endif //GGADV_CPU_H

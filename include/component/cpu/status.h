//
// Created by orzgg on 2020-09-02.
//

#include <array>
#include <cstdint>
#include <cstring>

#include <cpu_enum.h>

#ifndef GGADV_REGISTER_H
#define GGADV_REGISTER_H

namespace gg_core {
    class GbaInstance;

    namespace gg_cpu {
        struct Status {
            friend GbaInstance;
        public :
            Regs _regs;

            uint32_t CurrentInstruction() {
                return fetchedBuffer[pipelineCnt] ;
            } // CurrentInstruction()

            uint32_t CurrentPC_OnExec() {
                const uint32_t correction = GetCpuMode() == ARM ? 8 : 4 ;
                return _regs[ pc ] - correction ;
            }  // CurrentPC_OnExec()

            void WriteCPSR(uint32_t newCPSR) {
                /// todo: test
                E_OperationMode originalMode = static_cast<E_OperationMode>(_cpsr & 0x1fu);
                E_OperationMode newMode = static_cast<E_OperationMode>(newCPSR & 0x1fu);

                if (originalMode != newMode) {
                    unsigned *currentBank = GetBankRegDataPtr(originalMode),
                            *targetBank = GetBankRegDataPtr(newMode);

                    const int cpStart_old = (originalMode == FIQ) ? r8 : sp;
                    const int cpStart_new = (newMode == FIQ) ? r8 : sp;
                    const unsigned cpSize_old = lr - cpStart_old + 1;
                    const unsigned cpSize_new = lr - cpStart_new + 1;
                    // Store back current content to reg bank
                    memcpy(currentBank, _regs.data() + cpStart_old, sizeof(unsigned) * cpSize_old);
                    if (cpStart_old - cpStart_new < 0 && newMode == FIQ) {
                        // switch from a bank which is smaller than current mode's bank
                        // r8~r12 need to restored from usersys bank
                        memcpy(_regs.data() + r8, _registers_usrsys.data() + r8, sizeof(unsigned) * 5);
                    } // if

                    // Load banked register from new mode's reg bank
                    memcpy(_regs.data() + cpStart_new, targetBank, sizeof(unsigned) * cpSize_new);
                } // if

                _cpsr = newCPSR;
            }

            E_OperationMode GetOperationMode() {
                return static_cast<E_OperationMode>(_cpsr & 0x1f);
            } // GetOperationMode()

            E_CpuMode GetCpuMode() {
                return _cpsr & 0x20u ? THUMB : ARM;
            } // GetCpuMode()

            void ChangeCpuMode(E_CpuMode mode) {
                if (mode == THUMB)
                    _cpsr |= 0x1 << T ;
                else
                    _cpsr &= ~(0x1 << T);
            } // ChangeCpuMode()

            bool FIQ_Disable() {
                return _cpsr & 0x40u;
            } // FIQ_Disable()

            bool IRQ_Disable() {
                return _cpsr & 0x80u;
            } // IRQ_Disable()

            bool V() { return _cpsr & 0x10000000u; } // V()
            bool C() { return _cpsr & 0x20000000u; } // C()
            bool Z() { return _cpsr & 0x40000000u; } // Z()
            bool N() { return _cpsr & 0x80000000u; } // N()

            void SetV() { _cpsr |= (1 << 28); } // SetV()
            void ClearV() { _cpsr &= ~(1 << 28); } // ClearV()
            void SetC() { _cpsr |= (1 << 29); } // SetC()
            void ClearC() { _cpsr &= ~(1 << 29); } // ClearC()
            void SetZ() { _cpsr |= (1 << 30); } // SetZ()
            void ClearZ() { _cpsr &= ~(1 << 30); } // ClearZ()
            void SetN() { _cpsr |= (1 << 31); } // SetN()
            void ClearN() { _cpsr &= ~(1 << 31); } // ClearN()


        private :
            std::array<uint32_t, 3> fetchedBuffer;
            uint8_t pipelineCnt = 0;

            unsigned _cpsr = 0xd3;

            std::array<unsigned, 7> _registers_usrsys{};
            std::array<unsigned, 7> _registers_fiq{};
            std::array<unsigned, 2> _registers_svc{};
            std::array<unsigned, 2> _registers_abt{};
            std::array<unsigned, 2> _registers_irq{};
            std::array<unsigned, 2> _registers_und{};

            unsigned _spsr_fiq = E_OperationMode::FIQ,
                    _spsr_svc = E_OperationMode::SVC,
                    _spsr_abt = E_OperationMode::ABT,
                    _spsr_irq = E_OperationMode::IRQ,
                    _spsr_und = E_OperationMode::UND;

            unsigned *GetBankRegDataPtr(E_OperationMode mode) {
                switch (mode) {
                    case FIQ :
                        return _registers_fiq.data();
                    case IRQ :
                        return _registers_irq.data();
                    case SVC :
                        return _registers_svc.data();
                    case ABT :
                        return _registers_abt.data();
                    case UND :
                        return _registers_und.data();
                    case SYS :
                    case USR :
                        return _registers_usrsys.data();
                } // switch

                return nullptr;
            } // GetBankRegDataPtr()
        };
    }
}

#endif //GGADV_REGISTER_H

//
// Created by orzgg on 2020-09-02.
//

#include <array>
#include <cstdint>
#include <cstring>

#include <cpu_enum.h>

#ifndef GGADV_CPU_STATUS_H
#define GGADV_CPU_STATUS_H

class ggTest ;

namespace gg_core {
    namespace gg_cpu {
        struct CPU_Status {
            std::array<unsigned, 16> _regs;

            CPU_Status() {
                _regs.fill(0) ;
            }

            uint32_t CurrentInstruction() {
                return currentInstruction ;
            } // CurrentInstruction()

            uint32_t CurrentPC_OnExec() {
                const uint32_t correction = GetCpuMode() == ARM ? 8 : 4 ;
                return _regs[ pc ] - correction ;
            }  // CurrentPC_OnExec()

            uint32_t ReadCPSR() const {
                return _cpsr ;
            }

            uint32_t ReadSPSR() {
                switch (GetOperationMode()) {
                    case FIQ:
                        return _spsr_fiq ;
                    case IRQ:
                        return _spsr_irq ;
                    case SVC:
                        return _spsr_svc;
                    case ABT:
                        return _spsr_abt;
                    case UND:
                        return _spsr_und ;
                    default:
                        exit(-2) ;
                } // switch()
            }

            uint32_t ReadSPSR(E_OperationMode mode) {
                switch (mode) {
                    case FIQ:
                        return _spsr_fiq ;
                    case IRQ:
                        return _spsr_irq ;
                    case SVC:
                        return _spsr_svc;
                    case ABT:
                        return _spsr_abt;
                    case UND:
                        return _spsr_und ;
                    default:
                        exit(-2) ;
                } // switch()
            }

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

            void WriteSPSR(uint32_t value) {
                switch (GetOperationMode()) {
                    case FIQ:
                        _spsr_fiq = value ;
                        break ;
                    case IRQ:
                        _spsr_irq = value ;
                        break ;
                    case SVC:
                        _spsr_svc = value ;
                        break ;
                    case ABT:
                        _spsr_abt = value ;
                        break ;
                    case UND:
                        _spsr_und  = value ;
                        break ;
                    default:
                        exit(-2) ;
                } // switch()
            }

            E_OperationMode GetOperationMode() {
                return static_cast<E_OperationMode>(_cpsr & 0x1f);
            } // GetOperationMode()

            E_CpuMode GetCpuMode() {
                return _cpsr & 0x20u ? THUMB : ARM;
            } // GetCpuMode()

            bool F() { return _cpsr & 0x40u; } // F()
            bool I_Cycle() { return _cpsr & 0x80u; } // I()
            bool V() { return _cpsr & 0x10000000u; } // V()
            bool C() { return _cpsr & 0x20000000u; } // C()
            bool Z() { return _cpsr & 0x40000000u; } // Z()
            bool N() { return _cpsr & 0x80000000u; } // N()

            void SetF() { _cpsr |= (1 << 6); } // SetF()
            void ClearF() { _cpsr &= ~(1 << 6); } // ClearF()
            void SetI() { _cpsr |= (1 << 7); } // SetI()
            void ClearI() { _cpsr &= ~(1 << 7); } // ClearI()
            void SetV() { _cpsr |= (1 << 28); } // SetV()
            void ClearV() { _cpsr &= ~(1 << 28); } // ClearV()
            void SetC() { _cpsr |= (1 << 29); } // SetC()
            void ClearC() { _cpsr &= ~(1 << 29); } // ClearC()
            void SetZ() { _cpsr |= (1 << 30); } // SetZ()
            void ClearZ() { _cpsr &= ~(1 << 30); } // ClearZ()
            void SetN() { _cpsr |= (1 << 31); } // SetN()
            void ClearN() { _cpsr &= ~(1 << 31); } // ClearN()

            std::array<uint32_t, 2> fetchedBuffer;
            uint8_t fetchIdx = 0;
            uint32_t currentInstruction = 0x00 ;
            uint32_t _cpsr = 0xd3;
            uint32_t cycle = 0 ;

            std::array<unsigned, 7> _registers_usrsys{};
            std::array<unsigned, 7> _registers_fiq{};
            std::array<unsigned, 2> _registers_svc{};
            std::array<unsigned, 2> _registers_abt{};
            std::array<unsigned, 2> _registers_irq{};
            std::array<unsigned, 2> _registers_und{};

            unsigned _spsr_fiq = 0,
                    _spsr_svc = 0,
                    _spsr_abt = 0,
                    _spsr_irq = 0,
                    _spsr_und = 0;

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

                // todo: log undefined mode
                return nullptr;
            } // GetBankRegDataPtr()
        };
    }
}

#endif //GGADV_CPU_STATUS_H

//
// Created by orzgg on 2020-09-02.
//

#include <array>
#include <cstdint>
#include <cstring>

#include <bit_manipulate.h>

#include <cpu_enum.h>
#include <mem_enum.h>

#ifndef GGADV_CPU_STATUS_H
#define GGADV_CPU_STATUS_H

class ggTest;

namespace gg_core {
namespace gg_cpu {
class CPU;
using HandlerType = void (*)(gg_core::gg_cpu::CPU &);

struct CPU_Status {
  unsigned runState = 0x0;
  std::array<unsigned, 16> _regs;

  CPU_Status() {
	_regs.fill(0);
  }

  uint32_t CurrentPC_OnExec() {
	const uint32_t correction = instructionLength * 2;
	return _regs[pc] - correction;
  }  // CurrentPC_OnExec()

  uint32_t ReadCPSR() const {
	return _cpsr;
  }

  uint32_t ReadSPSR() {
	switch (GetOperationMode()) {
	case FIQ:return _spsr_fiq;
	case IRQ:return _spsr_irq;
	case SVC:return _spsr_svc;
	case ABT:return _spsr_abt;
	case UND:return _spsr_und;
	default:exit(-2);
	} // switch()
  }

  uint32_t ReadSPSR(E_OperationMode mode) {
	switch (mode) {
	case FIQ:return _spsr_fiq;
	case IRQ:return _spsr_irq;
	case SVC:return _spsr_svc;
	case ABT:return _spsr_abt;
	case UND:return _spsr_und;
	default:exit(-2);
	} // switch()
  }

  E_OperationMode GetOperationMode() {
	return static_cast<E_OperationMode>(_cpsr & 0x1f);
  } // GetOperationMode()

  E_CpuMode GetCpuMode() {
	return _cpsr & 0x20u ? THUMB : ARM;
  } // GetCpuMode()

  bool F() const { return _cpsr & 0x40u; } // F()
  bool I() const { return _cpsr & 0x80u; } // I()
  bool V() const { return _cpsr & 0x10000000u; } // V()
  bool C() const { return _cpsr & 0x20000000u; } // C()
  bool Z() const { return _cpsr & 0x40000000u; } // Z()
  bool N() const { return _cpsr & 0x80000000u; } // N()

  bool EQ() const { return Z(); }
  bool NE() const { return !Z(); }
  bool CS() const { return C(); }
  bool CC() const { return !C(); }
  bool MI() const { return N(); }
  bool PL() const { return !N(); }
  bool VS() const { return V(); }
  bool VC() const { return !V(); }
  bool HI() const { return C() && !Z(); }
  bool LS() const { return !C() || Z(); }
  bool GE() const { return N() == V(); }
  bool LT() const { return N() != V(); }
  bool GT() const { return !Z() && (N() == V()); }
  bool LE() const { return Z() || (N() != V()); }
  bool AL() const { return true; }

  std::array<bool (CPU_Status::*)()const, 16> conditionChecker{
	  &CPU_Status::EQ, // 0b0000
	  &CPU_Status::NE, // 0b0001
	  &CPU_Status::CS, // 0b0010
	  &CPU_Status::CC, // 0b0011
	  &CPU_Status::MI, // 0b0100
	  &CPU_Status::PL, // 0b0101
	  &CPU_Status::VS, // 0b0110
	  &CPU_Status::VC, // 0b0111
	  &CPU_Status::HI, // 0b1000
	  &CPU_Status::LS, // 0b1001
	  &CPU_Status::GE, // 0b1010
	  &CPU_Status::LT, // 0b1011
	  &CPU_Status::GT, // 0b1100
	  &CPU_Status::LE, // 0b1101
	  &CPU_Status::AL, // 0b1110
  };

  bool halt = false;

  std::array<uint32_t, 2> fetchedBuffer;
  uint8_t fetchIdx = 0;
  uint32_t currentInstruction = 0x00;

  uint32_t lastPC = 0x0;

  unsigned instructionLength = 4;
  HandlerType lastCallee = nullptr;

  std::array<unsigned, 7> _registers_usrsys{};
  std::array<unsigned, 7> _registers_fiq{};
  std::array<unsigned, 2> _registers_svc{};
  std::array<unsigned, 2> _registers_abt{};
  std::array<unsigned, 2> _registers_irq{};
  std::array<unsigned, 2> _registers_und{};

  unsigned _spsr_fiq = 0b10001,
	  _spsr_svc = 0b10011,
	  _spsr_abt = 0b10111,
	  _spsr_irq = 0b10010,
	  _spsr_und = 0b11011;

  unsigned *GetBankRegDataPtr(E_OperationMode mode) {
	switch (mode) {
	case FIQ :return _registers_fiq.data();
	case IRQ :return _registers_irq.data();
	case SVC :return _registers_svc.data();
	case ABT :return _registers_abt.data();
	case UND :return _registers_und.data();
	case SYS :
	case USR :return _registers_usrsys.data();
	} // switch

	// todo: log undefined mode
	return nullptr;
  } // GetBankRegDataPtr()

  gg_mem::E_AccessType fetchAccessType = gg_mem::S_Cycle;

  uint32_t (*iHash)(uint32_t) = nullptr;
  void (*Fetch)(CPU *, gg_mem::E_AccessType) = nullptr;
  void (*Tick)(CPU *) = nullptr;
  void (*RefillPipeline)(CPU *, gg_mem::CycleType, gg_mem::CycleType) = nullptr;
  HandlerType const *instructionTable = nullptr;
protected:
  uint32_t _cpsr = 0x0;
  uint32_t _elapsedClk = 0;
};
}
}

#endif //GGADV_CPU_STATUS_H

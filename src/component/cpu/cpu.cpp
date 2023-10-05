//
// Created by orzgg on 2020-09-02.
//

#include <gba_instance.h>
#include <memory>

#include <decoder.h>

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

#include <cpu_tick.h>

namespace gg_core::gg_cpu {
CPU::CPU(GbaInstance &instance) :
	CPU_Status(),
	_instance(instance),
	_mem(instance.mmu),
	armAsm(ASMMODE::ARM),
	thumbAsm(ASMMODE::THUMB) {
  /**
  ** fetchIdx point to pc+4
  ** !fetchIdx point to pc
  ** fetchidx always point to last fetched instruction
  **/
  iHash = ARM_instructionHashFunc;
  Fetch = &CPU::ARM_Fetch;
  Tick = CPUTickTable[0];
  RefillPipeline = &CPU::ARM_RefillPipeline;
  instructionTable = ARM_HandlerTable.data();

  fetchedBuffer[0] = _mem.Read<uint32_t>(0, gg_mem::N_Cycle);
  fetchedBuffer[1] = _mem.Read<uint32_t>(4, gg_mem::S_Cycle);

  _regs[r0] = 0xca5;

  _regs[pc] = 4;
  fetchIdx = 1;
} // CPU()

void CPU::CPU_StateChange() {
  const bool irqAck = (!!(_instance.IF & _instance.IE) & _instance.IME);
  runState = (runState & ~(1 << IRQ_BIT)) | ((I() & irqAck) << IRQ_BIT);
  Tick = CPUTickTable[runState];
} // CPU_StateChange()

void CPU::RaiseInterrupt(IRQ_TYPE irqType) {
  _instance.IF |= _BV(irqType);
  CPU_StateChange();
} // RaiseInterrupt()

void CPU::AddCycle(const unsigned int deltaClk, const char *reason) {
  std::cerr << "[CPU] elapsed cycle: " << _instance.cycleCounter << " (" << reason << ")" << std::endl;
  _elapsedClk += deltaClk;
}

void CPU::CPU_DebugTick() {
  currentInstruction = fetchedBuffer[!fetchIdx];
  std::string mode, instr, psr, info;

  auto OpMode2Str = [](unsigned mCode) {
	switch (mCode) {
	  case USR:return "USR";
	  case IRQ:return "IRQ";
	  case ABT:return "ABT";
	  case UND:return "UND";
	  case FIQ:return "FIQ";
	  case SVC:return "SVC";
	  case SYS:return "SYS";
	} // switch

	return "ERROR";
  };

  psr = fmt::format("\tcpsr: {:>#010x} spsr: ",
					ReadCPSR()
  );

  if (GetOperationMode() == USR || GetOperationMode() == SYS)
	psr += "No Value";
  else
	psr += fmt::format("{:>#010x}", ReadSPSR());

  info = fmt::format(reg4InfoStr,
					 _regs[r0], _regs[r1], _regs[r2], _regs[r3],
					 _regs[r4], _regs[r5], _regs[r6], _regs[r7],
					 _regs[r8], _regs[r9], _regs[r10], _regs[r11],
					 _regs[r12], _regs[sp], _regs[lr], _regs[pc] + instructionLength
  );

  if (GetCpuMode() == E_CpuMode::ARM) {
	mode = fmt::format("\tCPUMode: ARM, OpMode: {}", OpMode2Str(GetOperationMode()));
	instr = fmt::format("[{:#x}] {}", lastPC, armAsm.DASM(currentInstruction));
  } // if
  else {
	mode = fmt::format("\tCPUMode: THUMB, OpMode: {}", OpMode2Str(GetOperationMode()));
	instr = fmt::format("[{:#x}] {}", lastPC, thumbAsm.DASM(currentInstruction));
  } // else

  std::cerr << "CPU elapsed cycle: " << _elapsedClk << std::endl;
  std::cerr << "MMU elapsed cycle: " << _mem._elapsedCycle << std::endl;
  std::cerr << instr << std::endl;
  std::cerr << mode << std::endl;
  std::cerr << psr << std::endl;
  std::cerr << info << std::endl;

  _elapsedClk = 0;
  _mem._elapsedCycle = 0;

  const unsigned condition = [&]() {
	if (GetCpuMode() == E_CpuMode::ARM)
	  return (currentInstruction & 0xf0000000) >> 28;
	else
	  return static_cast<unsigned> (E_CondName::AL);
  }();

  auto checker = conditionChecker[condition];

  if (_instance.IME && I() && (_instance.IE & _instance.IF)) {
	Interrupt_impl<E_OperationMode::IRQ>(*this);
  } // if
  else {
	if ((this->*checker)())
	  instructionTable[iHash(currentInstruction)](*this);
	else
	  Fetch(this, gg_mem::S_Cycle);
  } // else
} // Tick()

void CPU::CPU_Test(uint32_t inst) {
  currentInstruction = inst;

  unsigned condition = 0x0;
  if (GetCpuMode() == E_CpuMode::ARM)
	condition = (inst & 0xf0000000) >> 28;
  else
	condition = E_CondName::AL;

  auto checker = conditionChecker[condition];
  lastCallee = instructionTable[iHash(inst)]; // for debug purpose

  if ((this->*checker)())
	instructionTable[iHash(inst)](*this);
  else
	Fetch(this, gg_mem::S_Cycle);
} // CPU_Test()

void CPU::ChangeCpuMode(E_CpuMode mode) {
  if (mode == THUMB) {
	_cpsr |= 0x1 << T;
	RefillPipeline = &CPU::THUMB_RefillPipeline;
	Fetch = &CPU::THUMB_Fetch;
	iHash = THUMB_instructionHashFunc;
	instructionTable = Thumb_HandlerTable.data();
	instructionLength = 2;
  } // if
  else {
	_cpsr &= ~(0x1 << T);
	RefillPipeline = &CPU::ARM_RefillPipeline;
	Fetch = &CPU::ARM_Fetch;
	iHash = ARM_instructionHashFunc;
	instructionTable = ARM_HandlerTable.data();
	instructionLength = 4;
  } // else
} // ChangeCpuMode()

void CPU::ChangeOperationMode(E_OperationMode newMode) {
  uint32_t oldStatus = _cpsr & ~0x1f;
  WriteCPSR(oldStatus | newMode);
} // CPU::ChangeOperationMode()

void CPU::ARM_RefillPipeline(CPU *self, gg_mem::CycleType first, gg_mem::CycleType second) {
  using namespace gg_cpu;

  unsigned pcBase = (self->_regs[pc] & ~0x3);

  self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase, first);
  self->fetchedBuffer[self->fetchIdx] = self->_mem.Read<uint32_t>(pcBase + 4, second);

  self->lastPC = pcBase;
  self->_regs[pc] = pcBase + 4;
} // RefillPipeline()

void CPU::THUMB_RefillPipeline(CPU *self, gg_mem::CycleType first, gg_mem::CycleType second) {
  // todo: thumb pipeline alignment mechanism for invalid access.
  using namespace gg_cpu;

  unsigned pcBase = (self->_regs[pc] & ~0x1);
  self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint16_t>(pcBase, first);
  self->fetchedBuffer[self->fetchIdx] = self->_mem.Read<uint16_t>(pcBase + 2, second);

  self->lastPC = pcBase;
  self->_regs[pc] = pcBase + 2;
} // RefillPipeline()

void CPU::ARM_Fetch(CPU *self, gg_mem::E_AccessType accessType) {
  self->lastPC = self->_regs[gg_cpu::pc];
  self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 4) & ~0x3;
  self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint32_t>(self->_regs[gg_cpu::pc], accessType);
  self->fetchIdx = !self->fetchIdx;
} // ARM_Fetch()

void CPU::THUMB_Fetch(CPU *self, gg_mem::E_AccessType accessType) {
  self->lastPC = self->_regs[gg_cpu::pc];
  self->_regs[gg_cpu::pc] = (self->_regs[gg_cpu::pc] + 2) & ~0x1;
  self->fetchedBuffer[!self->fetchIdx] = self->_mem.Read<uint16_t>(self->_regs[gg_cpu::pc], accessType);
  self->fetchIdx = !self->fetchIdx;
} // THUMB_Fetch()

void CPU::WriteCPSR(uint32_t newCPSR) {
  /// todo: test
  E_OperationMode originalMode = static_cast<E_OperationMode>(_cpsr & 0x1fu);
  E_OperationMode newMode = static_cast<E_OperationMode>(newCPSR & 0x1fu);

  // if new mode is not the same as old mode, and not switching between USR and SYS
  bool needBankSwap = (originalMode != newMode) && ((originalMode ^ newMode) != 0b01111);

  if (needBankSwap) {
	// specialize the swap logic for GBA's cpu(NO FIQ mode)
	unsigned *currentBank = GetBankRegDataPtr(originalMode);
	unsigned *targetBank = GetBankRegDataPtr(newMode);

	// Store back current content to reg bank
	*reinterpret_cast<uint64_t *>(currentBank) = *reinterpret_cast<uint64_t *>(_regs.data() + sp);
	// Load banked register from new mode's reg bank
	*reinterpret_cast<uint64_t *>(_regs.data() + sp) = *reinterpret_cast<uint64_t *>(targetBank);
  } // if

  if (TestBit(_cpsr, 7) != TestBit(newCPSR, 7))
	CPU_StateChange();

  _cpsr = newCPSR;
} // CPU::WriteCPSR()

void CPU::WriteSPSR(uint32_t value) {
  switch (GetOperationMode()) {
	case FIQ:_spsr_fiq = value;
	  break;
	case IRQ:_spsr_irq = value;
	  break;
	case SVC:_spsr_svc = value;
	  break;
	case ABT:_spsr_abt = value;
	  break;
	case UND:_spsr_und = value;
	  break;
	default:exit(-2);
  } // switch()
} // WriteSPSR()
}
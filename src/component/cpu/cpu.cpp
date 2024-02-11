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

const bool verbose = false;

namespace gg_core::gg_cpu {
const char* OpMode2Str(unsigned mCode) {

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
}

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
//  _mem.GetElapsedCycle(); // clear MMU's elapsed cycle for test purpose
  fetchIdx = 1;
//  currentInstruction = fetchedBuffer[0];
//  _registers_svc[0] = 0x03007fe0;
//  _registers_irq[0] = 0x03007fa0;
//  _registers_usrsys[0] = 0x03007f00;

  _cpsr = 0xd3; // Start CPU as System mode
//  _regs[sp] = 0x03007f00;
  _regs[pc] = 4;
} // CPU()

void CPU::CPU_StateChange() {
	ChangeCpuMode(GetCpuMode());
} // CPU_StateChange()

bool CPU::Interruptable(gg_io::E_FIELD_IRQ irqBit) const {
  return I() && _instance.IME && TestBit((_instance.IF & _instance.IE), irqBit);
}

void CPU::RaiseInterrupt(IRQ_TYPE irqType) {
  _instance.IF |= _BV(irqType);
  CPU_StateChange();
} // RaiseInterrupt()

void CPU::AddCycle(const unsigned int deltaClk, const char *reason) {
//  std::cerr << "[CPU] elapsed cycle: " << deltaClk << " (" << reason << ")" << std::endl;
  _elapsedClk += deltaClk;
}

void CPU::DumpStatusDASM() {
  std::string mode, instr, psr, info;

  psr = fmt::format("cpsr: {:0>8X} [{}{}{}{}{}{}{}]",
					ReadCPSR(),
					N() ? 'N' : '-',
					Z() ? 'Z' : '-',
					C() ? 'C' : '-',
					V() ? 'V' : '-',
					I() ? 'I' : '-',
					F() ? 'F' : '-',
					GetCpuMode() == THUMB ? 'T' : '-'
  );

//  if (GetOperationMode() == USR || GetOperationMode() == SYS)
//	psr += "No Value";
//  else
//	psr += fmt::format("0x{:0>8x}", ReadSPSR());

  info = fmt::format(reg4InfoStr,
					 _regs[r0], _regs[r1], _regs[r2], _regs[r3],
					 _regs[r4], _regs[r5], _regs[r6], _regs[r7],
					 _regs[r8], _regs[r9], _regs[r10], _regs[r11],
					 _regs[r12], _regs[sp], _regs[lr], _regs[pc]
  );

  if (GetCpuMode() == E_CpuMode::ARM) {
	mode = fmt::format("\tCPUMode: ARM, OpMode: {}", OpMode2Str(GetOperationMode()));
//	instr = fmt::format("{:0>8X}:  {:0>8X}",
//						lastPC,
//						currentInstruction);
	instr = fmt::format("{:0>8X}:  {:0>8X}\t{}",
	  lastPC,
	  currentInstruction,
	  armAsm.DASM(currentInstruction));
  } // if
  else {
//	mode = fmt::format("\tCPUMode: THUMB, OpMode: {}", OpMode2Str(GetOperationMode()));
	const bool isFormat19PartA = (currentInstruction & 0xf000) == 0xf000;
	if (isFormat19PartA) {
	  if (TestBit(currentInstruction, 11)) {
		instr = fmt::format("{:0>8X}:  ignored", lastPC);
	  } // if
	  else {
		std::string disasmResult = thumbAsm.DASM(currentInstruction | (fetchedBuffer[fetchIdx] << 16));
		instr = fmt::format("{:0>8X}:  {:0>4X} {:0>4X}\t{}",
							lastPC,
							currentInstruction,
							fetchedBuffer[fetchIdx],
							disasmResult);
//		instr = fmt::format("{:0>8X}:  {:0>4X} {:0>4X}",
//							lastPC,
//							currentInstruction,
//							fetchedBuffer[fetchIdx]);
	  } // else
	} // if
	else {
	  instr = fmt::format("{:0>8X}:  {:0>4X}\t{}", lastPC, currentInstruction, thumbAsm.DASM(currentInstruction));
//	  instr = fmt::format("{:0>8X}:  {:0>4X}", lastPC, currentInstruction);
	} // else
  } // else

//  std::cerr << "CPU elapsed cycle: " << _elapsedClk << std::endl;
//  std::cerr << "MMU elapsed cycle: " << _mem._elapsedCycle << std::endl;
//  std::cerr << mode << std::endl;
} // CPU::DumpStatus()

void CPU::DumpStatus() {
  std::string mode, instr, psr, info, io;

  io = fmt::format("VCOUNT: {:0>4}", _instance.VCOUNT);

  psr = fmt::format("cpsr: {:0>8X} [{}{}{}{}{}{}{}]",
	ReadCPSR(),
	N() ? 'N' : '-',
	Z() ? 'Z' : '-',
	C() ? 'C' : '-',
	V() ? 'V' : '-',
	I() ? 'I' : '-',
	F() ? 'F' : '-',
	GetCpuMode() == THUMB ? 'T' : '-'
  );

//  if (GetOperationMode() == USR || GetOperationMode() == SYS)
//	psr += "No Value";
//  else
//	psr += fmt::format("0x{:0>8x}", ReadSPSR());

  info = fmt::format(reg4InfoStr,
					 _regs[r0], _regs[r1], _regs[r2], _regs[r3],
					 _regs[r4], _regs[r5], _regs[r6], _regs[r7],
					 _regs[r8], _regs[r9], _regs[r10], _regs[r11],
					 _regs[r12], _regs[sp], _regs[lr], _regs[pc]
  );

  if (GetCpuMode() == E_CpuMode::ARM) {
	mode = fmt::format("\tCPUMode: ARM, OpMode: {}", OpMode2Str(GetOperationMode()));
	instr = fmt::format("{:0>8X}:  {:0>8X}",
	  lastPC,
	  currentInstruction);
//	instr = fmt::format("{:0>8X}:  {:0>8X}\t{}",
//	  lastPC,
//	  currentInstruction,
//	  armAsm.DASM(currentInstruction));
  } // if
  else {
//	mode = fmt::format("\tCPUMode: THUMB, OpMode: {}", OpMode2Str(GetOperationMode()));
	const bool isFormat19PartA = (currentInstruction & 0xf000) == 0xf000;
	if (isFormat19PartA) {
	  if (TestBit(currentInstruction, 11)) {
		instr = fmt::format("{:0>8X}:  ignored", lastPC);
	  } // if
	  else {
		std::string disasmResult = thumbAsm.DASM(currentInstruction | (fetchedBuffer[fetchIdx] << 16));
//		instr = fmt::format("{:0>8X}:  {:0>4X} {:0>4X}\t{}",
//							lastPC,
//							currentInstruction,
//							fetchedBuffer[fetchIdx],
//							disasmResult);
		instr = fmt::format("{:0>8X}:  {:0>4X} {:0>4X}",
							lastPC,
							currentInstruction,
							fetchedBuffer[fetchIdx]);
	  } // else
	} // if
	else {
//	  instr = fmt::format("{:0>8X}:  {:0>4X}\t{}", lastPC, currentInstruction, thumbAsm.DASM(currentInstruction));
	  instr = fmt::format("{:0>8X}:  {:0>4X}", lastPC, currentInstruction);
	} // else
  } // else

//  std::cerr << "CPU elapsed cycle: " << _elapsedClk << std::endl;
//  std::cerr << "MMU elapsed cycle: " << _mem._elapsedCycle << std::endl;
//  std::cerr << mode << std::endl;
} // CPU::DumpStatus()

unsigned CPU::GetElapsedCycle() {
  // CPU's elapsed cycle is the cycles that finish a instruction need.
  // In other words, it's the sum of CPU's elapsed cycle and MMU's elapsed cycle.
  unsigned result = _elapsedClk + _mem.GetElapsedCycle();
  _elapsedClk = 0;
  return result;
} // GetElapsedCycle()

void CPU::Step() {
//  DumpStatus();
  if (halt) {
	_instance.Follow(1);
	if (_instance.IF & _instance.IE) {
	  halt = false;
	} // if
  } // if
  else {
	if (_instance.IME && !I() && (_instance.IE & _instance.IF)) {
	  Interrupt_impl<E_OperationMode::IRQ>(*this);
	} // if
	else {
	  // Most of the time, fetchAccessType is S_Cycle, but when the instruction is
	  // STR*, the fetch access type will change to N_Cycle.
	  currentInstruction = fetchedBuffer[!fetchIdx];

	  const unsigned condition = [&]() {
		if (GetCpuMode() == E_CpuMode::ARM)
		  return (currentInstruction & 0xf0000000) >> 28;
		else
		  return static_cast<unsigned> (E_CondName::AL);
	  }();

	  auto checker = conditionChecker[condition];

//	if (_instance.totalCycle >= 7239611)
	  if (!verbose) {
//		if (_instance.totalCycle >= 79975267) {
//		  std::cout << std::endl;
//		} // if
	  } // if
	  else {
		DumpStatus();
	  } // else

	  Fetch(this, fetchAccessType);
	  fetchAccessType = gg_mem::S_Cycle;

	  if ((this->*checker)())
		instructionTable[iHash(currentInstruction)](*this);
	} // else
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
	const int srcIdx = newMode == FIQ ? r8 : sp;
	const int bankSize = newMode == FIQ ? 7 : 2;

	for (int i = 0 ; i < bankSize ; ++i) {
	  currentBank[i] = _regs[srcIdx + i]; // store reg value to current bank
	  _regs[srcIdx + i] = targetBank[i]; // load reg value from target bank
	} // for
  } // if

  _cpsr = newCPSR;
  CPU_StateChange();
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
  } // switch()
} // WriteSPSR()

void CPU::Idle(const unsigned cycles) {
  _instance.Follow(cycles);
} // Idle()
}
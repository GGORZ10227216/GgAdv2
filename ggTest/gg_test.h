//
// Created by jason4_lee on 2020-10-12.
//


#include <thread>
#include <future>
#include <utility>
#include <string>
#include <array>
#include <optional>
#include <cstdlib>

#include <gtest/gtest.h>
#include <arm_asm.h>

#include <gba_instance.h>
#include <core/core.h>
#include <gg_utility.h>
#include <loop_tool.h>
#include <core/core.h>

#include <arm_encoder.h>

#ifndef GGTEST_GG_TEST_H
#define GGTEST_GG_TEST_H

class ggTest : public testing::Test {
protected:
  Arm &egg = arm;
  gg_core::GbaInstance gbaInstance;
  gg_core::gg_mem::MMU &gg_mmu;
  gg_core::gg_cpu::CPU &instance;
  constexpr static char *testRomPath = "./testRom.gba";

  ArmAssembler gg_asm;
  ArmAssembler gg_tasm;

  ggTest() :
	  gbaInstance(testRomPath),
	  gg_mmu(gbaInstance.mmu),
	  instance(gbaInstance.cpu),
	  gg_tasm(ASMMODE::THUMB) {

  }

  constexpr uint hashArm(u32 instr) {
	return ((instr >> 16) & 0xFF0) | ((instr >> 4) & 0xF);
  }

  constexpr uint hashThumb(u16 instr) {
	return (instr >> 6);
  }

  uint32_t CheckStatus(const gg_core::gg_cpu::CPU &mine, const Arm &egg) {
	using namespace gg_core::gg_cpu;

	uint32_t status_flag = 0;
	for (int i = r0; i <= pc; ++i) {
	  if (mine._regs[i] != egg.regs[i])
		status_flag |= gg_core::_BV(i);
	} // for

	if (mine.ReadCPSR() != egg.cpsr)
	  status_flag |= gg_core::_BV(16);

	if (egg.pipe[0] != mine.fetchedBuffer[!mine.fetchIdx])
	  status_flag |= gg_core::_BV(17);
	if (egg.pipe[1] != mine.fetchedBuffer[mine.fetchIdx])
	  status_flag |= gg_core::_BV(18);

	return status_flag;
  }

  std::string Diagnose(const gg_core::gg_cpu::CPU &mine, const Arm &egg, uint32_t status_flag) const {
	using namespace gg_core::gg_cpu;

	std::string result;
	for (int i = r0; i <= 18; ++i) {
	  if (status_flag & gg_core::_BV(i)) {
		if (i < 16)
		  result += fmt::format("\t[X] r{}: mine={:x} ref={:x}\n", i, mine._regs[i], egg.regs[i]);
		else if (i == 16)
		  result += fmt::format("\t[X] cpsr: mine={:x} ref={:x}\n", mine.ReadCPSR(), egg.cpsr);
		else if (i == 17)
		  result += fmt::format("\t[X] pipeline[0]: mine={:x} ref={:x}\n",
								mine.fetchedBuffer[!mine.fetchIdx], egg.pipe[0]);
		else if (i == 18)
		  result += fmt::format("\t[X] pipeline[1]: mine={:x} ref={:x}\n",
								mine.fetchedBuffer[mine.fetchIdx], egg.pipe[1]);
	  } // if
	} // for

	return result;
  }

  virtual void SetUp() override {
	EggInit();
  }

  void EggInit() {
	const int argc = 2;
	static const char *argv[argc] = {
		"",
		testRomPath
	};

	core::init(argc, argv);
	std::copy(biosData.begin(), biosData.end(), mmu.bios.data.begin());
	core::reset();
  }

  void EggRun(Arm &egg_local, uint32_t instruction) {
	uint32_t inst_hash = hashArm(instruction);
	egg_local.regs[15] = (egg_local.regs[15] + 4) & ~0x3;
	egg_local.pipe[0] = egg_local.pipe[1];
	egg_local.pipe[1] = egg_local.readWord(egg_local.gprs[15]);

	std::invoke(egg_local.instr_arm[inst_hash], &egg_local, instruction);
  }

  void EggRunThumb(Arm &egg_local, uint16_t instruction) {
	uint32_t inst_hash = hashThumb(instruction);
	egg_local.regs[15] = (egg_local.regs[15] + 2) & ~0x1;

	const uint32_t nextInstruction = egg_local.pipe[1] & 0xffff;

	egg_local.pipe[1] = egg_local.readHalf(egg_local.gprs[15]) & 0xffff;
	egg_local.pipe[0] = nextInstruction;

	std::invoke(egg_local.instr_thumb[inst_hash], &egg_local, instruction);
  } // EggRunThumb()

  void GgInitToThumbState(gg_core::gg_cpu::CPU &local_cpu) {
	local_cpu._regs[0] = 0; // bypass 0xca5 emulation
	local_cpu._regs[15] = 0; // for test only

	local_cpu.ChangeCpuMode(gg_core::gg_cpu::THUMB);
	local_cpu.RefillPipeline(&local_cpu, gg_core::gg_mem::S_Cycle, gg_core::gg_mem::S_Cycle);
  }

  void CpuPC_Reset(Arm &egg_local, gg_core::gg_cpu::CPU &local_cpu) {
	egg_local.regs[15] = 0;
	local_cpu._regs[15] = 0;
  }

  void CpuPC_ResetThumb(Arm &egg_local, gg_core::gg_cpu::CPU &local_cpu) {
	local_cpu.ChangeCpuMode(gg_core::gg_cpu::THUMB);
	egg_local.cpsr.t = true;

	egg_local.regs[15] = 0;
	egg_local.pipe[0] = 0xabcd;
	egg_local.pipe[1] = 0x5566;

	local_cpu._regs[15] = 0;
	local_cpu.fetchedBuffer[!local_cpu.fetchIdx] = 0xabcd;
	local_cpu.fetchedBuffer[local_cpu.fetchIdx] = 0x5566;
  }
};

static constexpr std::array<const char *, 16> regNames{
	"r0", "r1", "r2", "r3", "r4", "r5",
	"r6", "r7", "r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15"
};

static constexpr std::array<const char *, 4> shiftNames{
	"lsl", "lsr", "asr", "ror"
};

template<typename A, size_t... Is, typename... RS, typename... VS>
void FillRegs_Impl(A &regs, std::tuple<RS...> &R, std::tuple<VS...> &V, std::index_sequence<Is...>) {
  ((regs[std::get<Is>(R)] = std::get<Is>(V)), ...);
}

template<typename A, typename... RS, typename... VS>
void FillRegs(A &regs, std::tuple<RS...> &R, std::tuple<VS...> &V) {
  constexpr size_t reg_idx_number = sizeof...(RS);
  constexpr size_t field_number = sizeof...(VS);
  static_assert(reg_idx_number == field_number);

  FillRegs_Impl(regs, R, V, std::make_index_sequence<reg_idx_number>{});
}

using WorkerResult = std::pair<std::string, std::future<unsigned int>>;

template<typename T, typename S>
using WorkerResult2 = std::pair<T, S>;

#endif //GGTEST_GG_TEST_H

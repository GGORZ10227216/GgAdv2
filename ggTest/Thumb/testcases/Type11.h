//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core::gg_cpu;

TEST_F(ggTest, Thumb_load_word_sp_based_offset
) {
auto TestMain = [&](uint32_t spValue, uint32_t areaBound) -> uint64_t {
  uint64_t t = 0;

  gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

  arm.cpsr.t = true;
  arm.flushHalf();

  GgInitToThumbState(local_cpu);

  auto task = [&]() {
	for (int offset = 0; offset < 0x100; ++offset) {
	  for (int RdNum = 0; RdNum < 8; ++RdNum) {
		uint16_t instruction = (0b1001 << 12) | (0b1 << 11) | (RdNum << 8) | offset;

		arm.regs[sp] = spValue;
		local_cpu._regs[sp] = spValue;

		arm.regs[pc] = spValue;
		local_cpu._regs[pc] = spValue;

		uint32_t targetDst = local_cpu._regs[sp] + (offset << 2);
		if (targetDst < spValue || targetDst >= areaBound) {
		  ++t;
		  continue;
		}

		EggRunThumb(arm, instruction);
		local_cpu.CPU_Test(instruction);

		uint32_t errFlag = CheckStatus(local_cpu, arm);
		std::string input = fmt::format("SP Value: {:#x}, Offset value: {:#x}\n",
										spValue, offset);

		ASSERT_TRUE((local_cpu.lastCallee == SP_RelativeLoadStore < true > ));
		ASSERT_TRUE((gbaInstance.mmu.bios_readBuf == mmu.bios.previous));
		ASSERT_TRUE(errFlag == 0)
			<< "#" << t << " of test\n"
			<< std::hex << "Errflag: " << errFlag << '\n'
			<< input
			<< gg_tasm.DASM(instruction) << " [" << instruction
			<< "]" << '\n'
			<< Diagnose(local_cpu, arm, errFlag);

		CpuPC_Reset(arm, local_cpu);
		++t;
	  } // for
	} // for
  };

  task();
  return t;
};

using namespace gg_core;
const auto areaList = gg_core::make_array(
	std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart),
	std::make_tuple(gg_mem::BIOS_end, E_BIOS_SIZE, gg_mem::onboardStart),
	std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
	std::make_tuple(gg_mem::onboardEnd, E_EWRAM_SIZE, gg_mem::onchipStart),
	std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
	std::make_tuple(gg_mem::onchipEnd, E_IWRAM_SIZE, gg_mem::ioStart),
	std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
	std::make_tuple(gg_mem::paletteEnd, E_PALETTE_SIZE, gg_mem::VRAM_Start),
	std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
	std::make_tuple(gg_mem::VRAM_End, E_VRAM_SIZE, gg_mem::OAM_Start),
	std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
	std::make_tuple(gg_mem::OAM_End, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
	std::make_tuple(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
	std::make_tuple(gg_mem::WAITSTATE_0_Start + E_ROM_BLOCK_SIZE / 2, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
	std::make_tuple(gg_mem::WAITSTATE_1_Start + E_ROM_BLOCK_SIZE, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start),
	std::make_tuple(gg_mem::WAITSTATE_1_Start + E_ROM_BLOCK_SIZE / 2, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start)
//            std::make_tuple(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE, gg_mem::SRAM_Start) // bypass eeprom test
);

for (
const auto &areaInfo
: areaList) {
auto [base, vaildAccessOffset, bound] = areaInfo;

if (base != 0 && base < 0x8000000) {
if (base == 0x7000'000) {
for (
int i = 0;
i<vaildAccessOffset;
++i) {
gbaInstance.mmu.
Write<uint16_t>(base
+i, static_cast
<uint16_t>(i), S_Cycle
);
arm.
writeHalf(base
+i, static_cast
<uint16_t>(i)
);
} // for
}
else {
for (
int i = 0;
i<vaildAccessOffset;
++i) {
gbaInstance.mmu.
Write<uint8_t>(base
+i, static_cast
<uint8_t>(i), S_Cycle
);
arm.
writeByte(base
+i, static_cast
<uint8_t>(i)
);
} // for
}
} // if

spdlog::info(fmt::format("[{}] from {:x} to {:x}", getpid(), base, base + 0x100)
);
TestMain(base, bound
);
spdlog::info(fmt::format("[{}] Test is PASSED", getpid())
);
} // for
}

TEST_F(ggTest, Thumb_store_word_sp_based_offset
) {
auto TestMain = [&](uint32_t spValue, uint32_t RdValue, uint32_t areaBound) -> uint64_t {
  uint64_t t = 0;

  gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

  arm.cpsr.t = true;
  arm.flushHalf();

  GgInitToThumbState(local_cpu);

  auto task = [&]() {
	for (int offset = 0; offset < 0x100; ++offset) {
	  for (int RdNum = 0; RdNum < 8; ++RdNum) {
		uint16_t instruction = (0b1001 << 12) | (RdNum << 8) | offset;

		arm.regs[RdNum] = RdValue;
		local_cpu._regs[RdNum] = RdValue;

		arm.regs[sp] = spValue;
		local_cpu._regs[sp] = spValue;

		arm.regs[pc] = spValue;
		local_cpu._regs[pc] = spValue;

		uint32_t targetDst = local_cpu._regs[sp] + (offset << 2);

		if (targetDst < spValue || targetDst >= areaBound) {
		  ++t;
		  continue;
		}

		EggRunThumb(arm, instruction);
		local_cpu.CPU_Test(instruction);

		uint32_t refReadBack = arm.readWordRotate(targetDst);
		uint32_t ggReadBack = gbaInstance.mmu.Read<uint32_t>(targetDst, gg_core::gg_mem::S_Cycle);

		uint32_t errFlag = CheckStatus(local_cpu, arm);
		std::string input = fmt::format("SP Value: {:#x}, Offset: {:#x}\n", spValue, offset);

		ASSERT_TRUE((local_cpu.lastCallee == SP_RelativeLoadStore < false > ));
		ASSERT_TRUE(refReadBack == ggReadBack)
			<< fmt::format("#{} mine: {:#x} ref: {:#x}", t, ggReadBack, refReadBack);
		ASSERT_TRUE(errFlag == 0)
			<< "#" << t << " of test\n"
			<< std::hex << "Errflag: " << errFlag << '\n'
			<< input
			<< gg_tasm.DASM(instruction) << " [" << instruction
			<< "]" << '\n'
			<< Diagnose(local_cpu, arm, errFlag);

		CpuPC_Reset(arm, local_cpu);
		++t;
	  } // for
	} // for
  };

  task();
  return t;
};

using namespace gg_core;
const auto areaList = gg_core::make_array(
	std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart),
	std::make_tuple(gg_mem::BIOS_end, E_BIOS_SIZE, gg_mem::onboardStart),
	std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
	std::make_tuple(gg_mem::onboardEnd, E_EWRAM_SIZE, gg_mem::onchipStart),
	std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
	std::make_tuple(gg_mem::onchipEnd, E_IWRAM_SIZE, gg_mem::ioStart),
	std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
	std::make_tuple(gg_mem::paletteEnd, E_PALETTE_SIZE, gg_mem::VRAM_Start),
	std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
	std::make_tuple(gg_mem::VRAM_End, E_VRAM_SIZE, gg_mem::OAM_Start),
	std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
	std::make_tuple(gg_mem::OAM_End, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
	std::make_tuple(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
	std::make_tuple(gg_mem::WAITSTATE_0_Start + E_ROM_BLOCK_SIZE / 2, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
	std::make_tuple(gg_mem::WAITSTATE_1_Start + E_ROM_BLOCK_SIZE, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start),
	std::make_tuple(gg_mem::WAITSTATE_1_Start + E_ROM_BLOCK_SIZE / 2, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start)
//            std::make_tuple(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE, gg_mem::SRAM_Start) // bypass eeprom test
);

const auto testData = make_array(
	0xdeadbeefu,
	0xaabbccddu,
	0x0a0b0c0du,
	0xc0d0e0f0u,
	0xffffffffu,
	0x00000000u
);

for (
const auto &areaInfo
: areaList) {
for (
const auto &testCase
: testData) {
auto [base, validAccessOffset, bound] = areaInfo;
spdlog::info(fmt::format("[{}] store [{:#x}] test  from {:x} to {:x}",
						 getpid(), testCase, base, base + 0x100)
);
TestMain(base, testCase, bound
);
spdlog::info(fmt::format("[{}] Test is PASSED", getpid())
);
} // for
} // for
}
}
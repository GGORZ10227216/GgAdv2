//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core::gg_cpu;

const auto testData = gg_core::make_array(
	0xdeadbeefu,
	0xaabbccddu,
	0x0a0b0c0du,
	0xc0d0e0f0u,
	0xffffffffu,
	0x00000000u,
	0x11111111u,
	0x0a1b2c3du,
	0xfeedcafeu
);

TEST_F(ggTest, Thumb_push
) {
int t = 0;
gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
arm.cpsr.
t = true;
arm.
flushHalf();

GgInitToThumbState(local_cpu);

auto task = [&](uint32_t spAddr) {
  int Rlist = 0;
  for (Rlist = 0; Rlist <= 0x1ff; ++Rlist) {
	for (int i = 0, j = 0; i <= 8; ++i) {
	  if (gg_core::TestBit(Rlist, i)) {
		if (i == 8) {
		  arm.regs[lr] = testData[j];
		  local_cpu._regs[lr] = testData[j];
		} // if
		else {
		  arm.regs[i] = testData[j];
		  local_cpu._regs[i] = testData[j];
		} // else

		++j;
	  } // if
	} // for

	bool Rbit = gg_core::TestBit(Rlist, 8);
	uint32_t instruction = (0b10110100 << 8) | (Rbit << 8) | (Rlist & 0xff);

	arm.regs[sp] = spAddr;
	local_cpu._regs[sp] = spAddr;

	std::string input = fmt::format("SP Value: {:#x}, Rlist: {:#x}\n",
									spAddr, (Rlist & 0xff));

	EggRunThumb(arm, instruction);
	local_cpu.CPU_Test(instruction);

	uint32_t errFlag = CheckStatus(local_cpu, arm);

	if (Rbit == 0)
	  ASSERT_TRUE((local_cpu.lastCallee == PushPop < false, false >));
	else
	  ASSERT_TRUE((local_cpu.lastCallee == PushPop < false, true >));

	for (int i = 8, j = 1; i >= 0; --i) {
	  if (gg_core::TestBit(Rlist, i)) {
		const uint32_t refReadback = arm.readWordRotate((spAddr - j * 4) & ~0x3);
		const uint32_t ggReadback = gbaInstance.mmu.Read<uint32_t>((spAddr - j * 4) & ~0x3, gg_core::gg_mem::S_Cycle);
		++j;

		if (i < 8) {
		  ASSERT_TRUE(arm.regs[i] == refReadback);
		  ASSERT_TRUE(ggReadback == refReadback);
		} // if
		else {
		  ASSERT_TRUE(arm.regs[lr] == refReadback);
		  ASSERT_TRUE(ggReadback == refReadback);
		} // else
	  } // if
	} // for

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
};

using namespace gg_core;
const auto areaList = gg_core::make_array(
	0x03007f00,
	0x03007f01,
	0x03007f02,
	0x03007f03
);

for (
const auto base
: areaList)
task(base);
}

TEST_F(ggTest, Thumb_pop
){
int t = 0;
gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
arm.cpsr.
t = true;
arm.
flushHalf();

GgInitToThumbState(local_cpu);

for (
int idx = 0x0300'0000, j = 0;
idx<gg_core::gg_mem::onchipEnd;
idx += 4) {
arm.
writeWord(idx, testData[j]
);
gbaInstance.mmu.
Write<uint32_t>(idx, testData[j], gg_core::gg_mem::S_Cycle
);
j = (j + 1) % testData.size();
} // for

auto task = [&](uint32_t spAddr) {
  int Rlist = 0;
  for (Rlist = 0; Rlist <= 0x1ff; ++Rlist) {
	for (int i = 0, j = 0; i <= 8; ++i) {
	  if (gg_core::TestBit(Rlist, i)) {
		if (i == 8) {
		  arm.regs[lr] = testData[j];
		  local_cpu._regs[lr] = testData[j];
		} // if
		else {
		  arm.regs[i] = testData[j];
		  local_cpu._regs[i] = testData[j];
		} // else

		++j;
	  } // if
	} // for

	bool Rbit = gg_core::TestBit(Rlist, 8);
	uint32_t instruction = (0b10110100 << 8) | (1 << 11) | (Rbit << 8) | (Rlist & 0xff);

	arm.regs[sp] = spAddr;
	local_cpu._regs[sp] = spAddr;

	std::string input = fmt::format("SP Value: {:#x}, Rlist: {:#x}\n",
									spAddr, (Rlist & 0xff));

	EggRunThumb(arm, instruction);
	local_cpu.CPU_Test(instruction);

	uint32_t errFlag = CheckStatus(local_cpu, arm);

	if (Rbit == 0)
	  ASSERT_TRUE((local_cpu.lastCallee == PushPop < true, false >));
	else
	  ASSERT_TRUE((local_cpu.lastCallee == PushPop < true, true >));

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
};

using namespace gg_core;
const auto areaList = gg_core::make_array(
	0x03007f00,
	0x03007f01,
	0x03007f02,
	0x03007f03
);

for (
const auto base
: areaList)
task(base);
}
}

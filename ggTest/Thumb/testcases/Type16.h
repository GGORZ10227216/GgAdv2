//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core;
using namespace gg_core::gg_cpu;

TEST_F(ggTest, Thumb_conditional_branch
) {
int t = 0;
gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
arm.
cpsr = 0xf3;
arm.
flushHalf();

GgInitToThumbState(local_cpu);

const auto areaList = gg_core::make_array(
	gg_mem::BIOS_start,
	gg_mem::BIOS_end,
	gg_mem::onboardStart,
	gg_mem::onboardEnd,
	gg_mem::onchipStart,
	gg_mem::onchipEnd,
	gg_mem::paletteStart,
	gg_mem::paletteEnd,
	gg_mem::VRAM_Start,
	gg_mem::VRAM_End,
	gg_mem::OAM_Start,
	gg_mem::OAM_End,
	gg_mem::WAITSTATE_0_Start,
	gg_mem::WAITSTATE_0_Start + E_ROM_BLOCK_SIZE / 2,
	gg_mem::WAITSTATE_1_Start,
	gg_mem::WAITSTATE_1_Start + E_ROM_BLOCK_SIZE / 2
);

for (
const uint32_t pcValue
: areaList) {
for (
int offset8 = 0;
offset8 < 0x100; ++ offset8) {
for (
int cond = 0x0;
cond < 0xf; ++cond) {
if (cond != 0xe) {
uint32_t instruction = (0b1101 << 12) | (cond << 8) | offset8;

for (
int testCpsr = 0x0;
testCpsr < 0x10; ++testCpsr) {
arm.
cpsr = (arm.cpsr & 0xff) | (testCpsr << 28);

gg_core::TestBit(testCpsr,
0) ? local_cpu.
SetV() : local_cpu
.
ClearV();
gg_core::TestBit(testCpsr,
1) ? local_cpu.
SetC() : local_cpu
.
ClearC();
gg_core::TestBit(testCpsr,
2) ? local_cpu.
SetZ() : local_cpu
.
ClearZ();
gg_core::TestBit(testCpsr,
3) ? local_cpu.
SetN() : local_cpu
.
ClearN();

arm.regs[ pc ] =
pcValue;
local_cpu._regs[ pc ] =
pcValue;

EggRunThumb(arm, instruction
);
local_cpu.
CPU_Test(instruction);

uint32_t errFlag = CheckStatus(local_cpu, arm);

ASSERT_TRUE((local_cpu
.lastCallee == ConditionalBranch));
ASSERT_TRUE(errFlag
== 0)
<< "#" << t << " of test\n"
<< std::hex << "Errflag: " << errFlag << '\n'
<< fmt::format("NZCV: {:x} pcbase: {:#X} offset: {:d}\n", testCpsr, pcValue, offset8)
<< gg_tasm.
DASM(instruction)
<< " [" << instruction
<< "]" << '\n'
<<
Diagnose(local_cpu, arm, errFlag
);

CpuPC_Reset(arm, local_cpu
);
++
t;
} // for
} // if
} // for
} // for
} // for
}
}

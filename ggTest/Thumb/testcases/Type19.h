//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core;
using namespace gg_core::gg_cpu;

TEST_F(ggTest, Thumb_long_branch_with_link
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
int offsetA = 0;
offsetA < 0x800; ++ offsetA) {
uint32_t instructionA = (0b1111 << 12) | offsetA;
for (
int offsetB = 0;
offsetB < 0x800; ++ offsetB) {
uint32_t instructionB = (0b11111 << 11) | offsetB;

arm.regs[ pc ] =
pcValue;
local_cpu._regs[ pc ] =
pcValue;

EggRunThumb(arm, instructionA
);
local_cpu.
CPU_Test(instructionA);

ASSERT_TRUE((local_cpu
.lastCallee == LongBranch<false>));
uint32_t errFlag = CheckStatus(local_cpu, arm);

if (errFlag == 0) {
uint32_t targetAddr = arm.regs[lr] + (offsetB << 1);
if (targetAddr >=
gg_mem::WAITSTATE_2_Start &&targetAddr<gg_mem::WAITSTATE_2_Start
+ ROM_BLOCK_SIZE)
continue;; // bypass WS2

uint32_t oldLR = arm.regs[lr];

EggRunThumb(arm, instructionB
);
local_cpu.
CPU_Test(instructionB);

ASSERT_TRUE((local_cpu
.lastCallee == LongBranch<true>));
errFlag = CheckStatus(local_cpu, arm);
ASSERT_TRUE(errFlag
== 0)
<< "#" << t << " of test(insruction B failed)\n"
<< std::hex << "Errflag: " << errFlag << '\n'
<< fmt::format("pcbase: {:#x} offset: {:#x}\n", pcValue, (offsetA << 12) | (offsetB << 1))
<< gg_tasm.
DASM((instructionB
<< 16) | instructionA) << " [" << ((instructionB << 16) | instructionA)
<< "]" << '\n'
<<
Diagnose(local_cpu, arm, errFlag
);

arm.regs[ lr ] =
oldLR;
local_cpu._regs[ lr ] =
oldLR;
} // if
else {
ASSERT_TRUE(errFlag
== 0)
<< "#" << t << " of test(insruction A failed)\n"
<< std::hex << "Errflag: " << errFlag << '\n'
<< gg_tasm.
DASM((instructionB
<< 16) | instructionA) << " [" << ((instructionB << 16) | instructionA)
<< "]" << '\n'
<<
Diagnose(local_cpu, arm, errFlag
);
} // else
} // for

++
t;
} // for
} // for
}
}

//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core::gg_cpu;

TEST_F(ggTest, Thumb_add_imm_to_sp
) {
gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

for (
int Sbit = 0;
Sbit < 2; ++Sbit) {
for (
int offset = 0;
offset < 0x80; ++offset) {
uint32_t instruction = (0b10110000 << 8) | (Sbit << 7) | offset;

arm.cpsr.
t = true;
arm.
flushHalf();

GgInitToThumbState(local_cpu);

arm.regs[sp] = 0x0300'0000;
local_cpu._regs[sp] = 0x0300'0000;

std::string input = fmt::format("SP Value: 0x0200'0000, Offset value: {:#x}\n", static_cast<int8_t>(offset << 2));

EggRunThumb(arm, instruction
);
local_cpu.
CPU_Test(instruction);

uint32_t errFlag = CheckStatus(local_cpu, arm);

if (Sbit == 0)
ASSERT_TRUE((local_cpu
.lastCallee == SP_Offset<false>));
else
ASSERT_TRUE((local_cpu
.lastCallee == SP_Offset<true>));
ASSERT_TRUE(errFlag
== 0)
<< "#" << offset << " of test\n"
<< std::hex << "Errflag: " << errFlag << '\n'
<< input
<< gg_tasm.
DASM(instruction)
<< " [" << instruction
<< "]" << '\n'
<<
Diagnose(local_cpu, arm, errFlag
);

CpuPC_Reset(arm, local_cpu
);
} // for
} // for
}
}

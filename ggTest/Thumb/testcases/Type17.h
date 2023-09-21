//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
using namespace gg_core;
using namespace gg_core::gg_cpu;

TEST_F(ggTest, Thumb_swi
) {
int t = 0;
gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

arm.
flushHalf();
GgInitToThumbState(local_cpu);

for (
int value8 = 0;
value8 < 0x100; ++value8) {
uint32_t instruction = (0b11011111 << 8) | value8;

local_cpu.
ChangeCpuMode(THUMB);

arm.
cpsr = 0xf0;
local_cpu.WriteCPSR(0xf0);

arm.regs[pc] = 0x0800'2410;
local_cpu._regs[pc] = 0x0800'2410;

EggRunThumb(arm, instruction
);
local_cpu.
CPU_Test(instruction);

uint32_t errFlag = CheckStatus(local_cpu, arm);

ASSERT_TRUE((local_cpu
.lastCallee == SoftInterrupt));
ASSERT_TRUE((local_cpu
.
ReadCPSR()
== arm.cpsr));
ASSERT_TRUE((local_cpu
.
ReadSPSR()
== arm.spsr));
ASSERT_TRUE(errFlag
== 0)
<< "#" << t << " of test\n"
<< std::hex << "Errflag: " << errFlag << '\n'
<< gg_tasm.
DASM(instruction)
<< " [" << instruction
<< "]" << '\n'
<<
Diagnose(local_cpu, arm, errFlag
);

CpuPC_Reset(arm, local_cpu
);
arm.regs[lr] = 0;
local_cpu._regs[lr] = 0;
++
t;
} // for
}
}

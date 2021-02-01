//
// Created by buildmachine on 2021-02-01.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    TEST_F(ggTest, svc_test) {
        Arm egg;
        GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        uint32_t instruction = 0xef000000 ;

        instance._status.WriteCPSR(0x10) ;
        egg.cpsr = 0x10 ;

        uint32_t inst_hash = hashArm(instruction);
        std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
        instance.CPUTick_Debug(instruction);

        std::cout << instance._status._regs[ lr ] << " " << egg.regs[ 14 ] << std::endl ;
        uint32_t errFlag = CheckStatus(instance, egg);
        ASSERT_TRUE(errFlag == 0 )
            << std::hex << "Errflag: " << errFlag << '\n'
            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
            << Diagnose(instance, egg, errFlag);
    }
}
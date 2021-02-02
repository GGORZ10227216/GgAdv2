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

    TEST_F(ggTest, ldrt_test) {
        GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        instance._status.WriteCPSR(0x10) ;
        // fill usr reg
        for (int i = 0 ; i < 16 ; ++i)
            instance._status._regs[ i ] = 0x0200'0000 + i ;

        instance._mem.Write32(0x02000000, 0xdeadbeefu) ;

        instance._status.WriteCPSR(0x13) ;
        uint32_t instruction = 0xe4b0e000 ; // ldrt lr, [r0]

        instance.CPUTick_Debug(instruction);

        ASSERT_TRUE(instance._status._regs[ sp ] == 0);
        ASSERT_TRUE(instance._status._regs[ lr ] == 0);

        instance._status.WriteCPSR(0x10) ;
        ASSERT_TRUE(instance._status._regs[ sp ] == 0x02000000 + sp) ;
        ASSERT_TRUE(instance._status._regs[ lr ] == 0xdeadbeef);
    }

    TEST_F(ggTest, strt_test) {
        GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        instance._status.WriteCPSR(0x10) ;
        // fill usr reg
        for (int i = 0 ; i < 16 ; ++i)
            instance._status._regs[ i ] = 0x0200'0000 + i ;

        instance._status.WriteCPSR(0x13) ;
        instance._status._regs[ sp ] =  0xdeadbeef ;

        uint32_t instruction = 0xe4a0d000 ; // strt lr, [r0]
        instance.CPUTick_Debug(instruction);

        ASSERT_TRUE(instance._mem.Read32(0x02000000) == 0x02000000 + sp) ;
    }
}
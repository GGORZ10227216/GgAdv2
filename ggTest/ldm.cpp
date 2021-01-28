//
// Created by buildmachine on 2021-01-28.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    TEST_F(ggTest, ldmed_test) {
        // ldmed --> pre-increment load, [L,P,U] == [1,1,1]
        uint32_t t = 0 ;
        Arm egg;
        GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        TestField wFlag(0,1,1) ;
        E_RegName targetRn = r4 ;
        TestField regList(0, 0xffff, 1) ;

        for (int i = 0x3000000 ; i <= 0x3007fff ; i += 4) {
            instance._mem.Write32(i, 0xabcdabcd + i) ;
            egg.writeWord(i, 0xabcdabcd + i) ;
        } // for

        for (int i = 0 ; i < 16 ; ++i) {
            instance._status._regs[ i ] = 0;
            egg.regs[ i ] = 0 ;
        } // for

        auto testMain = [&]() {
            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, true, true, false, wFlag.value, true, r4, regList.value
            ) ;

            egg.regs[ r4 ] = 0x03000000 ; // OWRAM
            instance._status._regs[ r4 ] = 0x03000000 ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUTick_Debug(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0 )
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag);
        };

        TEST_LOOPS(testMain, regList) ;
        std::cout << "Test performed: " << t << std::endl;
    }
}
//
// Created by buildmachine on 2020-12-16.
//
#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu;
    using MULLRegSet = std::tuple<uint8_t, uint8_t, uint8_t>;

    TEST_F(ggTest, b_test) {
        using namespace gg_core;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt);
        CPU instance(mmu); ;
        ArmAssembler gg_asm;

        unsigned int t = 0;
        TestField offsetValue(0, 0xffffff, 1);

        auto TestMain = [&]() {
            ++t;

            uint32_t instruction = MakeBranchInstruction<Cond, L, Offset>(
                    AL, false, offsetValue.value
            );

            egg.regs[15] = 0 ;
            instance._regs[15] = 0 ;

            uint32_t inst_hash = hashArm(instruction);

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: offset_raw: {:x}\n", offsetValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
        };

        TEST_LOOPS(TestMain, offsetValue);
        fmt::print("Total performed tests: {}\n", t);
    }

    TEST_F(ggTest, bl_test) {
        using namespace gg_core;

        Arm egg;
                gg_mem::MMU mmu(std::nullopt);
        CPU instance(mmu);
        ArmAssembler gg_asm;

        unsigned int t = 0;
        TestField offsetValue(0, 0xffffff, 1);

        auto TestMain = [&]() {
            ++t;

            uint32_t instruction = MakeBranchInstruction<Cond, L, Offset>(
                    AL, true, offsetValue.value
            );

            egg.regs[15] = 0 ;
            instance._regs[15] = 0 ;

            uint32_t inst_hash = hashArm(instruction);

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: offset_raw: {:x}\n", offsetValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
        };

        TEST_LOOPS(TestMain, offsetValue);
        fmt::print("Total performed tests: {}\n", t);
    }

    TEST_F(ggTest, bx_test) {
        using namespace gg_core;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        unsigned int t = 0;
        TestField targetRn(0, 0xe, 1); // Let's check bx r15 behavior in another test.
        TestField RnValue(0x2000000, 0x203ffff, 1); // jump only in WRAM

        auto TestMain = [&]() {
            ++t;

            uint32_t instruction = 0xe12fff10 | targetRn.value ;

            egg.regs[targetRn.value] = RnValue.value ;
            instance._regs[targetRn.value] = RnValue.value ;

            uint32_t inst_hash = hashArm(instruction);

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: Rn={:x}", RnValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
        };

        TEST_LOOPS(TestMain, targetRn, RnValue);
        fmt::print("Total performed tests: {}\n", t);
    }
}

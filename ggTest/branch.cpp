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
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0;
        TestField offsetValue(0, 0xffffff, 0x111);

        auto TestMain = [&]() {
            ++t;

            uint32_t instruction = MakeBranchInstruction<Cond, L, Offset>(
                    AL, false, offsetValue.value
            );

            egg.regs[15] = 0 ;
            instance._status._regs[15] = 0 ;

            uint32_t inst_hash = hashArm(instruction);

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUTick_Debug(instruction);

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
}

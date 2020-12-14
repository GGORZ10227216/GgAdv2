//
// Created by buildmachine on 2020-12-14.
//

//
// Created by orzgg on 2020-12-12.
//
#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu;
    using MULLRegSet = std::tuple<uint8_t, uint8_t, uint8_t>;
    constexpr static std::array<MULLRegSet, 15 * 14 * 13> testcase_reg_number_set = []() constexpr {
        std::array<MULLRegSet, 15 * 14 * 13> result;
        uint16_t flag_reg_used = 0x0;

        int idx = 0;
        for (int RdHi = 0; RdHi < 15; ++RdHi) {
            flag_reg_used |= gg_core::_BV(RdHi);
            for (int RdLo = 0; RdLo < 15; ++RdLo) {
                if (!(flag_reg_used & gg_core::_BV(RdLo))) {
                    flag_reg_used |= gg_core::_BV(RdLo);

                    for (int Rm = 0; Rm < 15; ++Rm) {
                        if (!(flag_reg_used & gg_core::_BV(Rm))) {
                            flag_reg_used |= gg_core::_BV(Rm);

                            result[idx++] = std::make_tuple(RdHi, RdLo, Rm);

                            flag_reg_used &= ~(gg_core::_BV(Rm));
                        } // if
                    } // for

                    flag_reg_used &= ~(gg_core::_BV(RdLo));
                } // if
            } // for

            flag_reg_used &= ~(gg_core::_BV(RdHi));
        } // for

        return result;
    }();

    TEST_F(ggTest, umull_cpsr_test) {
        using namespace gg_core;

        auto task = [&](uint8_t cpsr) {
            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm;

            unsigned int t = 0;
            TestField targetRs(0, 0xe, 1);
            TestField RsValue(0, 0xffffffff, 0x11111111);
            TestField RmValue(0, 0xffffffff, 0x11111111);
            TestField RegSetNum(0, 2729, 1);

            auto TestMain = [&]() {
                ++t;

                const auto &current_reg_set = testcase_reg_number_set[RegSetNum.value];
                uint8_t targetRdHi = std::get<0>(current_reg_set);
                uint8_t targetRdLo = std::get<1>(current_reg_set);
                uint8_t targetRm = std::get<2>(current_reg_set);

                uint32_t instruction = MakeMULLInstruction<Cond, U, A, S, RdHi, RdLo, Rs, Rm>(
                        AL, false, false, true,
                        targetRdHi,
                        targetRdLo,
                        targetRs.value,
                        targetRm
                );

                auto idx = std::make_tuple(targetRs.value, targetRm);
                auto val = std::make_tuple(RsValue.value, RmValue.value);
                FillRegs(instance._status._regs, idx, val);
                FillRegs(egg.regs, idx, val);

                egg.cpsr = (cpsr << 28) | 0xd3;
                instance._status.WriteCPSR(cpsr << 28 | 0xd3);

                uint32_t inst_hash = hashArm(instruction);

                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg);
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format("Testcase: Rs: {:x}, Rm: {:x}\n", RsValue.value,
                                                           RmValue.value)
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag);


            };

            TEST_LOOPS(TestMain, RsValue, RmValue, RegSetNum, targetRs);
            return t;
        };

        std::vector<WorkerResult> workers;
        for (int i = 0; i < 16; ++i) {
            std::string cpsr = fmt::format("{:X}", i);
            std::cout << '[' << cpsr << "]" << "start!" << std::endl;
            auto result = std::make_pair(
                    cpsr,
                    std::async(std::launch::async, task, i)
            );

            workers.push_back(std::move(result));
        } // for

        for (auto &t : workers)
            fmt::print("[CPSR:{}] Total performed tests: {}\n", t.first, t.second.get());
    }

    TEST_F(ggTest, smull_cpsr_test) {
        using namespace gg_core;

        auto task = [&](uint8_t cpsr) {
            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm;

            unsigned int t = 0;
            TestField targetRs(0, 0xe, 1);
            TestField RsValue(0, 0xffffffff, 0x11111111);
            TestField RmValue(0, 0xffffffff, 0x11111111);
            TestField RegSetNum(0, 2729, 1);

            auto TestMain = [&]() {
                ++t;

                const auto &current_reg_set = testcase_reg_number_set[RegSetNum.value];
                uint8_t targetRdHi = std::get<0>(current_reg_set);
                uint8_t targetRdLo = std::get<1>(current_reg_set);
                uint8_t targetRm = std::get<2>(current_reg_set);

                uint32_t instruction = MakeMULLInstruction<Cond, U, A, S, RdHi, RdLo, Rs, Rm>(
                        AL, true, false, true,
                        targetRdHi,
                        targetRdLo,
                        targetRs.value,
                        targetRm
                );

                auto idx = std::make_tuple(targetRs.value, targetRm);
                auto val = std::make_tuple(RsValue.value, RmValue.value);
                FillRegs(instance._status._regs, idx, val);
                FillRegs(egg.regs, idx, val);

                egg.cpsr = (cpsr << 28) | 0xd3;
                instance._status.WriteCPSR(cpsr << 28 | 0xd3);

                uint32_t inst_hash = hashArm(instruction);

                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg);
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format("Testcase: Rs: {:x}, Rm: {:x}\n", RsValue.value,
                                                           RmValue.value)
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag);


            };

            TEST_LOOPS(TestMain, RsValue, RmValue, RegSetNum, targetRs);
            return t;
        };

        std::vector<WorkerResult> workers;
        for (int i = 0; i < 16; ++i) {
            std::string cpsr = fmt::format("{:X}", i);
            std::cout << '[' << cpsr << "]" << "start!" << std::endl;
            auto result = std::make_pair(
                    cpsr,
                    std::async(std::launch::async, task, i)
            );

            workers.push_back(std::move(result));
        } // for

        for (auto &t : workers)
            fmt::print("[CPSR:{}] Total performed tests: {}\n", t.first, t.second.get());
    }
}
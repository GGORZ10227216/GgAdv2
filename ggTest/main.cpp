//
// Created by jason4_lee on 2020-10-12.
//
#include <gg_test.h>

namespace {
    TEST_F(ggTest, mov_rd_rm_shift_rs_test) {
        std::cout << "Test start" << std::endl;
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);

        for (int Rd = r0; Rd <= r14; ++Rd) {
            for (int Rm = r0; Rm <= r14; ++Rm) {
                for (int Rs = r0; Rs <= r14; ++Rs) {
                    for (int shift = lsl; shift <= ror; ++shift) {
                        for (int i = 0; i < TestCases.size(); ++i) {
                            instance._status._regs[Rd] = TestCases[i][0];
                            instance._status._regs[Rm] = TestCases[i][1];
                            instance._status._regs[Rs] = TestCases[i][2];

                            arm.regs[Rd] = TestCases[i][0];
                            arm.regs[Rm] = TestCases[i][1];
                            arm.regs[Rs] = TestCases[i][2];

                            std::string instruction = fmt::format(
                                    "movs {}, {}, {} {}",
                                    regNames[Rd],
                                    regNames[Rm],
                                    shiftNames[shift],
                                    regNames[Rs]
                            );

                            uint32_t binary = ASM(instruction);

                            std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary);
                            instance.CPUTick_Debug(binary);

                            CheckStatus(instance, arm, instruction, fmt::format("R{}=0x{:x} R{}=0x{:x} R{}={}",
                                                                                Rd, TestCases[i][0],
                                                                                Rm, TestCases[i][1],
                                                                                Rs, TestCases[i][2]
                            ));
                        } // for
                    } // for
                } // for
            } // for
        } // for
    }

    TEST_F(ggTest, mov_rd_r15_shift_rs_test) {
        std::cout << "Test start" << std::endl;
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);

        for (int Rd = r0; Rd <= r14; ++Rd) {
            uint32_t Rm = r15 ;
            for (int Rs = r0; Rs <= r14; ++Rs) {
                for (int shift = lsl; shift <= ror; ++shift) {
                    for (int i = 0; i < TestCases.size(); ++i) {
                        instance._status._regs[Rd] = TestCases[i][0];
                        instance._status._regs[Rm] = TestCases[i][1];
                        instance._status._regs[Rs] = TestCases[i][2];

                        arm.regs[Rd] = TestCases[i][0];
                        arm.regs[Rm] = TestCases[i][1];
                        arm.regs[Rs] = TestCases[i][2];

                        std::string instruction = fmt::format(
                                "movs {}, {}, {} {}",
                                regNames[Rd],
                                regNames[Rm],
                                shiftNames[shift],
                                regNames[Rs]
                        );

                        uint32_t binary = ASM(instruction);

                        std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary);
                        instance.CPUTick_Debug(binary);

                        CheckStatus(instance, arm, instruction, fmt::format("R{}=0x{:x} R{}=0x{:x} R{}={}",
                                                                            Rd, TestCases[i][0],
                                                                            Rm, TestCases[i][1],
                                                                            Rs, TestCases[i][2]
                        ));
                    } // for
                } // for
            } // for
        } // for
    }
}
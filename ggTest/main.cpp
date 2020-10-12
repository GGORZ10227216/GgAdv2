//
// Created by jason4_lee on 2020-10-12.
//
#include <gg_test.h>

namespace {
    TEST_F(ggTest, mov_rd_rm_shift_rs_test) {
        std::cout << "Test start" << std::endl ;
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);

        using TestCase = std::array<uint32_t, 3>;
        std::array<TestCase, 11> TestCases {
                TestCase { 0, 0, 0 },
                TestCase { 0, 0, 1 },
                TestCase { 0, 0, 31 },
                TestCase { 1, 0, 0 },
                TestCase { 0, 1, 0 },
                TestCase { 1, 0, 31 },
                TestCase { 0, 1, 31 },
                TestCase { 0xffffffff, 0, 0 },
                TestCase { 0, 0xffffffff, 0 },
                TestCase { 1, 0xffffffff, 31 },
                TestCase { 0xffffffff, 1, 1 }
        };

        for (int Rd = r0; Rd <= r14; ++Rd) {
            for (int Rm = r0; Rm <= r14; ++Rm) {
                for (int Rs = r0; Rs <= r14; ++Rs) {
                    for (int shift = lsl; shift <= ror; ++shift) {
                        for (int i = 0 ; i < 11 ; ++i) {
                            instance._status._regs[Rd] = TestCases[i][0] ;
                            instance._status._regs[Rm] = TestCases[i][1] ;
                            instance._status._regs[Rs] = TestCases[i][2] ;

                            arm.regs[Rd] = TestCases[i][0] ;
                            arm.regs[Rm] = TestCases[i][1] ;
                            arm.regs[Rs] = TestCases[i][2] ;

                            std::string instruction = fmt::format(
                                    "movs {}, {}, {} {}",
                                    regNames[Rd],
                                    regNames[Rm],
                                    shiftNames[shift],
                                    regNames[Rs]
                            );

                            uint32_t binary = ASM(instruction) ;
                            std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary) ;
                            instance.CPUTick_Debug(binary) ;
                            std::cout << instruction << std::endl;
                            CheckStatus(instance, arm) ;
                        } // for
                    } // for
                } // for
            } // for
        } // for
    }
}
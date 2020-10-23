//
// Created by jason4_lee on 2020-10-12.
//
#include <gg_test.h>
#include <thread>

namespace {
    TEST_F(ggTest, mov_rd_rm_shift_imm_test) {
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler assembler;

        uint32_t t = 0;
        for (int Rd = r0; Rd <= r14; ++Rd) {
            for (int Rm = r0; Rm <= r15; ++Rm) {
                for (int shift = lsl; shift <= ror; ++shift) {
                    for (int i = 0; i < TestCases.size(); ++i) {
                        ++t ;

                        instance._status._regs[Rd] = TestCases[i][0];
                        instance._status._regs[Rm] = TestCases[i][1];

                        arm.regs[Rd] = TestCases[i][0];
                        arm.regs[Rm] = TestCases[i][1];

                        std::string instruction = fmt::format(
                                "movs {}, {}, {} #{}",
                                regNames[Rd],
                                regNames[Rm],
                                shiftNames[shift],
                                TestCases[i][2]
                        );

                        uint32_t binary = assembler.ASM(instruction);

                        std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary);
                        instance.CPUTick_Debug(binary);

                        CheckStatus(instance, arm, instruction, fmt::format("TestCase: R{}=0x{:x} R{}=0x{:x} imm={}",
                                                                            Rd, TestCases[i][0],
                                                                            Rm, TestCases[i][1],
                                                                            TestCases[i][2]
                        ));
                    } // for
                } // for
            } // for
        } // for

        std::cout << t << std::endl ;
    }

    TEST_F(ggTest, mov_rd_imm_test) {
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler assembler;

        uint32_t t = 0;
        for (int Rd = r0; Rd <= r14; ++Rd) {
            std::string instruction = fmt::format(
                    "movs {}, #{}",
                    regNames[Rd],
                    0x10000000
            );

            uint32_t binary = assembler.ASM(instruction);

            std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary);
            instance.CPUTick_Debug(binary);

            CheckStatus(instance, arm, instruction, "");
        } // for
    }

    TEST_F(ggTest, mov_rd_rm_shift_rs_test) {
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler assembler;

        uint32_t t = 0;
        for (int Rd = r0; Rd <= r14; ++Rd) {
            for (int Rm = r0; Rm <= r15; ++Rm) {
                for (int Rs = r0; Rs <= r15; ++Rs) {
                    for (int shift = lsl; shift <= ror; ++shift) {
                        for (int i = 73; i < TestCases.size(); ++i) {
                            ++t ;
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

                            uint32_t binary = assembler.ASM(instruction);

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

        std::cout << t << std::endl ;
    }

    TEST_F(ggTest, mov_r0_r1_shift_r2_full_test_threaded) {
        std::cout << std::thread::hardware_concurrency() << " thread available" << std::endl;
        uint32_t Rd = r0, Rm = r1, Rs = r2;
        auto worker = [=](int RsStart, int loopCnt) {
            Arm arm;
            gg_core::GbaInstance instance(std::nullopt);

            for (int i = RsStart; i < RsStart + loopCnt; ++i) {
                for (uint64_t RmVal = 0; RmVal <= 0xffffffff; ++RmVal) {
                    for (int shift = lsl; shift <= ror; ++shift) {
                        instance._status._regs[Rd] = 0;
                        instance._status._regs[Rm] = RmVal;
                        instance._status._regs[Rs] = i;

                        arm.regs[Rd] = 0;
                        arm.regs[Rm] = RmVal;
                        arm.regs[Rs] = i;

                        uint32_t binary = 0xe1b00211 | (shift << 5);

                        std::invoke(arm.instr_arm[hashArm(binary)], &arm, binary);
                        instance.CPUTick_Debug(binary);

                        ASSERT_EQ(instance._status._regs[Rd], arm.regs[Rd]) << RmVal << " " << i << " " << shift;
                        ASSERT_EQ(instance._status._regs[Rm], arm.regs[Rm]) << RmVal << " " << i << " " << shift;
                        ASSERT_EQ(instance._status._regs[Rs], arm.regs[Rs]) << RmVal << " " << i << " " << shift;
                        ASSERT_EQ(instance._status.ReadCPSR(), arm.cpsr) << RmVal << " " << i << " " << shift;
                    } // for
                } // for
            } // for
        };

        std::vector<std::thread> workers;
        int RsBase = 0, threadCnt = std::thread::hardware_concurrency();
        int loopPerThread = 32 / threadCnt;

        for (int i = 0; i < threadCnt; ++i) {
            std::cout << "Worker initialized[" << RsBase << "," << RsBase + loopPerThread << "]" << std::endl;
            workers.push_back(std::thread(worker, RsBase, loopPerThread));
            RsBase += loopPerThread;
        } // for

        for (auto &t : workers)
            t.join();
    }

    TEST_F(ggTest, mov_rd_r15_shift_rs_test) {
        Arm arm;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler assembler;

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

                        uint32_t binary = assembler.ASM(instruction);

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

    TEST_F(ggTest, test_test) {
        constexpr std::array<const char*, 16> operations {
                "and", "eor", "sub", "rsb",
                "add", "adc", "sbc", "rsc",
                "tst", "teq", "cmp", "cmn",
                "orr", "mov", "bic", "mvn"
        } ;

        auto worker = [&](int operation) {
            Arm arm;
            gg_core::GbaInstance instance(std::nullopt);

            constexpr static std::array<const char*, 4> shiftTypes {
                    "lsl", "lsr", "asr", "ror"
            };

            uint8_t Rd = r0, Rn = r0, Rm = r0, Rs = r4 ;
            for (uint64_t RnVal = 0 ; RnVal <= 0xffffffff ; RnVal += 0x11111111) {
                for (uint64_t RmVal = 0 ; RmVal <= 0xffffffff ; RmVal += 0x11111111) {
                    for (uint64_t RsVal = 0 ; RsVal <= 0x1ff ; RsVal += 0x1) {
                        for (int rgNum = 0 ; rgNum <= 0xff ; ++rgNum) {
                            Rn = gg_core::BitFieldValue<uint8_t, 0, 4>(rgNum) ;
                            Rm = gg_core::BitFieldValue<uint8_t, 4, 4>(rgNum) ;

                            for (int s = 0 ; s < 1 ; ++s) {
                                uint32_t instruction = s ? 0xe0100410 : 0xe0000410 ;
                                for (int shiftType = lsl ; shiftType <= ror ; ++shiftType) {
                                    instruction |= Rn << 16 ;
                                    instruction |= Rm ;
                                    instruction |= shiftType << 5 ;

                                    std::invoke(arm.instr_arm[hashArm(instruction)], &arm, instruction);
                                    instance.CPUTick_Debug(instruction);

                                    auto CheckStatus = [&]() {
                                        for (int i = r0 ; i <= r15 ; ++i) {
                                            ASSERT_EQ(instance._status._regs[i], arm.regs[i])
                                                                        << "#" << i
                                                                        << "\tInstruction: " << std::hex << instruction << '\n'
                                                                        << "\tTestcast: " << fmt::format("Rn: {}, Rm: {}, Rs: {}, shift: {}\n",
                                                                                                         RnVal, RmVal, RsVal, shiftType) ;
                                        } // for


                                        ASSERT_EQ(instance._status.ReadCPSR(), arm.cpsr)
                                                                    << "\tInstruction: " << instruction << '\n'
                                                                    << "\t Testcast: " << fmt::format(
                                                                            "Rn: {}, Rm: {}, Rs: {}, shift: {}\n",
                                                                            RnVal, RmVal, RsVal, shiftType) ;
                                    };

                                    CheckStatus() ;
                                } // for
                            } // for
                        } // for
                    } // for
                } // for
            } // for
        };

        std::vector<std::thread> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << '[' << operations[i] << ']' << "start!" << std::endl ;
            workers.emplace_back(worker, i);
        } // for

        for (auto& t : workers) {
            t.join();
        } // for
    }
}
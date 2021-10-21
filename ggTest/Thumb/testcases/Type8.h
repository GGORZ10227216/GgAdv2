//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, Thumb_load_sign_extended_halfword) {
        auto TestMain = [&](uint32_t RbValue, uint32_t RoValue, uint32_t areaBound) -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RbNum = 0; RbNum < 8; ++RbNum) {
                    for (int RoNum = 0 ; RoNum < 8 ; ++RoNum) {
                        for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                            if (RdNum == RbNum || RdNum == RoNum)
                                continue;

                            uint16_t instruction = (0b0101001 << 9)|(0b11 << 10)|(RoNum << 6)|(RbNum << 3)|RdNum;

                            arm.regs[RbNum] = RbValue;
                            local_cpu._regs[RbNum] = RbValue;

                            arm.regs[RoNum] = RoValue;
                            local_cpu._regs[RoNum] = RoValue;

                            arm.regs[pc] = RbValue ;
                            local_cpu._regs[pc] = RbValue ;

                            uint32_t targetDst = local_cpu._regs[RbNum] + local_cpu._regs[RoNum] ;
                            if (targetDst < RbValue || targetDst >= areaBound) {
                                ++t ;
                                continue;
                            }

                            EggRunThumb(arm, instruction);
                            local_cpu.CPU_Test(instruction);

                            uint32_t errFlag = CheckStatus(local_cpu, arm);
                            std::string input = fmt::format("Base RegValue: {:#x}, Offset RegValue: {:#x}\n",
                                                            RbValue, RoValue);

                            ASSERT_TRUE((local_cpu.lastCallee == LoadStoreRegOffsetSignEx<true, true>));
                            ASSERT_TRUE(errFlag == 0)
                                                        << "#" << t << " of test\n"
                                                        << std::hex << "Errflag: " << errFlag << '\n'
                                                        << input
                                                        << gg_tasm.DASM(instruction) << " [" << instruction
                                                        << "]" << '\n'
                                                        << Diagnose(local_cpu, arm, errFlag);

                            CpuPC_Reset(arm, local_cpu);
                            ++t;
                        } // for
                    } // for
                } // for
            };

            task();
//            fmt::print("[{}] LDR base: {:#x} offset: {:#x} total_t: {}\r", std::this_thread::get_id(), RbValue, RoValue, t);
            return t;
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
            std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart),
            std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
            std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
            std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
            std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
            std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
            std::make_tuple(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
            std::make_tuple(gg_mem::WAITSTATE_1_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start)
//            std::make_tuple(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE, gg_mem::SRAM_Start) // bypass eeprom test
        ) ;

        for (const auto& areaInfo : areaList) {
            auto [base, vaildAccessOffset, bound] = areaInfo ;

            if (base != 0 && base < 0x8000000) {
                if (base == 0x7000'000) {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint16_t>(base+i, static_cast<uint16_t>(i), S_Cycle) ;
                        arm.writeHalf(base+i, static_cast<uint16_t>(i));
                    } // for
                }
                else {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint8_t>(base+i, static_cast<uint8_t>(i), S_Cycle) ;
                        arm.writeByte(base+i, static_cast<uint8_t>(i));
                    } // for
                }
            } // if

            int step = (bound - base)/8 ;

            for (int childNum = 0 ; childNum < 8 ; ++childNum) {
                pid_t PID = fork();

                if (PID == 0) {
                    spdlog::info(fmt::format("[{}] from {:x} to {:x}",
                                             getpid(), base + step*childNum, base + step*(childNum + 1))) ;

                    int i = 0 ;
                    for (int currentOffset = 0; currentOffset < step ; ++currentOffset) {
                        TestMain(base + step*childNum, currentOffset, bound) ;
                        i++ ;
                    } // for

                    spdlog::info(fmt::format("[{}] {} access", getpid(), i)) ;
                    exit(-1);
                } // if
                else if (PID < 0)
                    exit(-3) ;
            } // for

            int p = 0 ;
            while (p < 8) {
                waitpid(WAIT_ANY, NULL, 0);
                ++p;
            } // while

//            TestMain(0x9800000, 0, 0x0a00'0000) ;
        } // for
    }

    TEST_F(ggTest, Thumb_load_sign_extended_byte) {
        auto TestMain = [&](uint32_t RbValue, uint32_t RoValue, uint32_t areaBound) -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RbNum = 0; RbNum < 8; ++RbNum) {
                    for (int RoNum = 0 ; RoNum < 8 ; ++RoNum) {
                        for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                            if (RdNum == RbNum || RdNum == RoNum)
                                continue;

                            uint16_t instruction = (0b0101001 << 9)|(0b01 << 10)|(RoNum << 6)|(RbNum << 3)|RdNum;

                            arm.regs[RbNum] = RbValue;
                            local_cpu._regs[RbNum] = RbValue;

                            arm.regs[RoNum] = RoValue;
                            local_cpu._regs[RoNum] = RoValue;

                            arm.regs[pc] = RbValue ;
                            local_cpu._regs[pc] = RbValue ;

                            uint32_t targetDst = local_cpu._regs[RbNum] + local_cpu._regs[RoNum] ;
                            if (targetDst < RbValue || targetDst >= areaBound) {
                                ++t ;
                                continue;
                            }

                            EggRunThumb(arm, instruction);
                            local_cpu.CPU_Test(instruction);

                            uint32_t errFlag = CheckStatus(local_cpu, arm);
                            std::string input = fmt::format("Base RegValue: {:#x}, Offset RegValue: {:#x}\n",
                                                            RbValue, RoValue);

                            ASSERT_TRUE((local_cpu.lastCallee == LoadStoreRegOffsetSignEx<false, true>));
                            ASSERT_TRUE(errFlag == 0)
                                                        << "#" << t << " of test\n"
                                                        << std::hex << "Errflag: " << errFlag << '\n'
                                                        << input
                                                        << gg_tasm.DASM(instruction) << " [" << instruction
                                                        << "]" << '\n'
                                                        << Diagnose(local_cpu, arm, errFlag);

                            CpuPC_Reset(arm, local_cpu);
                            ++t;
                        } // for
                    } // for
                } // for
            };

            task();
//            fmt::print("[{}] LDR base: {:#x} offset: {:#x} total_t: {}\r", std::this_thread::get_id(), RbValue, RoValue, t);
            return t;
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
                std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart),
                std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
                std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
                std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
                std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
                std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
                std::make_tuple(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
                std::make_tuple(gg_mem::WAITSTATE_1_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start)
//            std::make_tuple(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE, gg_mem::SRAM_Start) // bypass eeprom test
        ) ;

        for (const auto& areaInfo : areaList) {
            auto [base, vaildAccessOffset, bound] = areaInfo ;

            if (base != 0 && base < 0x8000000) {
                if (base == 0x7000'000) {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint16_t>(base+i, static_cast<uint16_t>(i), S_Cycle) ;
                        arm.writeHalf(base+i, static_cast<uint16_t>(i));
                    } // for
                }
                else {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint8_t>(base+i, static_cast<uint8_t>(i), S_Cycle) ;
                        arm.writeByte(base+i, static_cast<uint8_t>(i));
                    } // for
                }
            } // if

            int step = (bound - base)/8 ;

            for (int childNum = 0 ; childNum < 8 ; ++childNum) {
                pid_t PID = fork();

                if (PID == 0) {
                    spdlog::info(fmt::format("[{}] from {:x} to {:x}",
                                             getpid(), base + step*childNum, base + step*(childNum + 1))) ;

                    int i = 0 ;
                    for (int currentOffset = 0; currentOffset < step ; ++currentOffset) {
                        TestMain(base + step*childNum, currentOffset, bound) ;
                        i++ ;
                    } // for

                    spdlog::info(fmt::format("[{}] {} access", getpid(), i)) ;
                    exit(-1);
                } // if
                else if (PID < 0)
                    exit(-3) ;
            } // for

            int p = 0 ;
            while (p < 8) {
                waitpid(WAIT_ANY, NULL, 0);
                ++p;
            } // while

//            TestMain(0x9800000, 0, 0x0a00'0000) ;
        } // for
    }
//
    TEST_F(ggTest, Thumb_load_halfword) {
        auto TestMain = [&](uint32_t RbValue, uint32_t RoValue, uint32_t areaBound) -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RbNum = 0; RbNum < 8; ++RbNum) {
                    for (int RoNum = 0 ; RoNum < 8 ; ++RoNum) {
                        for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                            if (RdNum == RbNum || RdNum == RoNum)
                                continue;

                            uint16_t instruction = (0b0101001 << 9)|(0b10 << 10)|(RoNum << 6)|(RbNum << 3)|RdNum;

                            arm.regs[RbNum] = RbValue;
                            local_cpu._regs[RbNum] = RbValue;

                            arm.regs[RoNum] = RoValue;
                            local_cpu._regs[RoNum] = RoValue;

                            arm.regs[pc] = RbValue ;
                            local_cpu._regs[pc] = RbValue ;

                            uint32_t targetDst = local_cpu._regs[RbNum] + local_cpu._regs[RoNum] ;
                            if (targetDst < RbValue || targetDst >= areaBound) {
                                ++t ;
                                continue;
                            }

//                            if (RoValue == 0x1 && t == 7)
//                                std::cout << std::endl ;

                            EggRunThumb(arm, instruction);
                            local_cpu.CPU_Test(instruction);

                            uint32_t errFlag = CheckStatus(local_cpu, arm);
                            std::string input = fmt::format("Base RegValue: {:#x}, Offset RegValue: {:#x}\n",
                                                            RbValue, RoValue);

                            ASSERT_TRUE((local_cpu.lastCallee == LoadStoreRegOffsetSignEx<true, false>));
                            ASSERT_TRUE(errFlag == 0)
                                                        << "#" << t << " of test\n"
                                                        << std::hex << "Errflag: " << errFlag << '\n'
                                                        << input
                                                        << gg_tasm.DASM(instruction) << " [" << instruction
                                                        << "]" << '\n'
                                                        << Diagnose(local_cpu, arm, errFlag);

                            CpuPC_Reset(arm, local_cpu);
                            ++t;
                        } // for
                    } // for
                } // for
            };

            task();
//            fmt::print("[{}] LDR base: {:#x} offset: {:#x} total_t: {}\r", std::this_thread::get_id(), RbValue, RoValue, t);
            return t;
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
                std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart),
                std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
                std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
                std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
                std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
                std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start),
                std::make_tuple(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_1_Start),
                std::make_tuple(gg_mem::WAITSTATE_1_Start, E_ROM_BLOCK_SIZE, gg_mem::WAITSTATE_2_Start)
//            std::make_tuple(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE, gg_mem::SRAM_Start) // bypass eeprom test
        ) ;

        for (const auto& areaInfo : areaList) {
            auto [base, vaildAccessOffset, bound] = areaInfo ;

            if (base != 0 && base < 0x8000000) {
                if (base == 0x7000'000) {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint16_t>(base+i, static_cast<uint16_t>(i), S_Cycle) ;
                        arm.writeHalf(base+i, static_cast<uint16_t>(i));
                    } // for
                }
                else {
                    for (int i = 0 ; i < vaildAccessOffset; ++i) {
                        gbaInstance.mmu.Write<uint8_t>(base+i, static_cast<uint8_t>(i), S_Cycle) ;
                        arm.writeByte(base+i, static_cast<uint8_t>(i));
                    } // for
                }
            } // if

            int step = (bound - base)/8 ;

            for (int childNum = 0 ; childNum < 8 ; ++childNum) {
                pid_t PID = fork();

                if (PID == 0) {
                    spdlog::info(fmt::format("[{}] from {:x} to {:x}",
                                             getpid(), base + step*childNum, base + step*(childNum + 1))) ;

                    int i = 0 ;
                    for (int currentOffset = 0; currentOffset < step ; ++currentOffset) {
                        TestMain(base + step*childNum, currentOffset, bound) ;
                        i++ ;
                    } // for

                    spdlog::info(fmt::format("[{}] {} access", getpid(), i)) ;
                    exit(-1);
                } // if
                else if (PID < 0)
                    exit(-3) ;
            } // for

            int p = 0 ;
            while (p < 8) {
                waitpid(WAIT_ANY, NULL, 0);
                ++p;
            } // while

//            TestMain(0x9800000, 0, 0x0a00'0000) ;
        } // for
    }
//
    TEST_F(ggTest, Thumb_store_halfword_with_reg_offset) {
        auto TestMain = [&](uint32_t RbValue, uint32_t RoValue, uint32_t RdValue, uint32_t areaBound) -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RbNum = 0; RbNum < 8; ++RbNum) {
                    for (int RoNum = 0 ; RoNum < 8 ; ++RoNum) {
                        for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                            if (RdNum == RbNum || RdNum == RoNum)
                                continue;

                            uint16_t instruction = (0b0101001 << 9)|(RoNum << 6)|(RbNum << 3)|RdNum;

                            arm.regs[r3] = RdValue ;
                            local_cpu._regs[r3] = RdValue ;

                            arm.regs[RbNum] = RbValue;
                            local_cpu._regs[RbNum] = RbValue;

                            arm.regs[RoNum] = RoValue;
                            local_cpu._regs[RoNum] = RoValue;

                            arm.regs[pc] = RbValue ;
                            local_cpu._regs[pc] = RbValue ;

                            uint32_t targetDst = local_cpu._regs[RbNum] + local_cpu._regs[RoNum] ;
                            if (targetDst < RbValue || targetDst >= areaBound) {
                                ++t ;
                                continue;
                            }


                            EggRunThumb(arm, instruction);
                            local_cpu.CPU_Test(instruction);

                            // still remain 32bit read, to check we don't mess up other byte
                            uint32_t refReadBack = arm.readWordRotate(targetDst) ;
                            uint32_t ggReadBack = gbaInstance.mmu.Read<uint32_t>(targetDst, gg_core::gg_mem::S_Cycle) ;

                            uint32_t errFlag = CheckStatus(local_cpu, arm);
                            std::string input = fmt::format("Base RegValue: {:#x}, Offset RegValue: {:#x}\n",
                                                            RbValue, RoValue);

                            ASSERT_TRUE((local_cpu.lastCallee == LoadStoreRegOffsetSignEx<false, false>));
                            ASSERT_TRUE(refReadBack == ggReadBack)
                                                        << fmt::format("#{} mine: {:#x} ref: {:#x}, offset: {:#x}", t, ggReadBack, refReadBack, RoValue) ;
                            ASSERT_TRUE(errFlag == 0)
                                                        << "#" << t << " of test\n"
                                                        << std::hex << "Errflag: " << errFlag << '\n'
                                                        << input
                                                        << gg_tasm.DASM(instruction) << " [" << instruction
                                                        << "]" << '\n'
                                                        << Diagnose(local_cpu, arm, errFlag);

                            CpuPC_Reset(arm, local_cpu);
                            ++t;
                        } // for
                    } // for
                } // for
            };

            task();
//            fmt::print("[{}] LDR base: {:#x} offset: {:#x} total_t: {}\r", std::this_thread::get_id(), RbValue, RoValue, t);
            return t;
        };

        using namespace gg_core;
        const auto areaList = make_array(
                std::make_tuple(gg_mem::onboardStart, E_EWRAM_SIZE, gg_mem::onchipStart),
                std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
                std::make_tuple(gg_mem::paletteStart, E_PALETTE_SIZE, gg_mem::VRAM_Start),
                std::make_tuple(gg_mem::VRAM_Start, E_VRAM_SIZE, gg_mem::OAM_Start),
                std::make_tuple(gg_mem::OAM_Start, E_OAM_SIZE, gg_mem::WAITSTATE_0_Start)
        ) ;

        const auto testData = make_array(
                0xdeadbeefu,
                0xaabbccddu,
                0x0a0b0c0du,
                0xc0d0e0f0u,
                0xffffffffu,
                0x00000000u
        ) ;

        for (const auto& areaInfo : areaList) {
            for (const auto& testcase : testData) {
                auto [base, offset, bound] = areaInfo ;
                int step = (bound - base)/8 ;

                for (int childNum = 0 ; childNum < 8 ; ++childNum) {
                    pid_t PID = fork();

                    if (PID == 0) {
                        spdlog::info(fmt::format("[{}] from {:x} to {:x}", getpid(), base + step*childNum,
                                                 base + step*(childNum + 1))) ;

                        int i = 0 ;
                        for (int currentOffset = 0; currentOffset < step ; ++currentOffset) {
                            TestMain(base + step*childNum, currentOffset, testcase, bound) ;
                            i++ ;
                        } // for

                        spdlog::info(fmt::format("[{}] {} access", getpid(), i)) ;
                        exit(-1);
                    } // if
                    else if (PID < 0)
                        exit(-3) ;
                } // for

                int p = 0 ;
                while (p < 8) {
                    waitpid(WAIT_ANY, NULL, 0);
                    ++p;
                } // while()
            } // for

//            TestMain(0x1c00000, 1, 0x2000000) ;
        } // for
    }
}

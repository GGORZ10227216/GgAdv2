//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu;

    void Type5CalleeCheek(CPU &local_cpu, const unsigned Op, const bool H1, const bool H2) {
        const int hashcode = (Op << 2) | (H1 << 1) | H2;
        switch (hashcode) {
            case 0b0001:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<ADD, false, true>));
                break;
            case 0b0010:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<ADD, true, false>));
                break;
            case 0b0011:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<ADD, true, true>));
                break;

            case 0b0101:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<CMP, false, true>));
                break;
            case 0b0110:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<CMP, true, false>));
                break;
            case 0b0111:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<CMP, true, true>));
                break;

            case 0b1001:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<MOV, false, true>));
                break;
            case 0b1010:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<MOV, true, false>));
                break;
            case 0b1011:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<MOV, true, true>));
                break;

            case 0b1100:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<0, false, false>));
                break;
            case 0b1101:
                ASSERT_TRUE((local_cpu.lastCallee == HiRegOperation_BX<0, false, true>));
                break;
            default:
                throw std::logic_error("Invalid Op number");
        } // switch
    } // Op2Shift()

    TEST_F(ggTest, Thumb_HiReg) {
        auto TestMain = [&](const unsigned Op, bool HiRd, bool HiRs, const uint32_t RsValue,
                            const uint32_t RdValue) -> uint64_t {
            uint64_t t = 0;

            arm.cpsr.t = true ; // for thumb ReadUnused()
            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
            GgInitToThumbState(local_cpu);

            CpuPC_ResetThumb(arm, local_cpu);

            const int RdStart = HiRd ? 8 : 0;
            const int RsStart = HiRs ? 8 : 0;

            auto task = [&]() {
                for (int RsNum = RsStart; RsNum < RsStart + 8; ++RsNum) {
                    for (int RdNum = RdStart; RdNum < RdStart + 8; ++RdNum) {
                        uint16_t instruction =
                                (0b010001 << 10) | (Op << 8) | (HiRd << 7) | (HiRs << 6) | ((RsNum - RsStart) << 3) | (RdNum - RdStart);

                        arm.regs[RsNum] = RsValue;
                        local_cpu._regs[RsNum] = RsValue;

                        arm.regs[RdNum] = RdValue;
                        local_cpu._regs[RdNum] = RdValue;

                        EggRunThumb(arm, instruction);
                        local_cpu.CPU_Test(instruction);

                        uint32_t errFlag = CheckStatus(local_cpu, arm);
                        std::string input = fmt::format("Original Rd(R{}): {:#x} Rs(R{}): {:#x}\n",
                                                        RdNum, RdValue, RsNum, RsValue);

                        Type5CalleeCheek(local_cpu, Op, HiRd, HiRs);

                        ASSERT_TRUE(errFlag == 0)
                                                    << "#" << t << " of test\n"
                                                    << std::hex << "Errflag: " << errFlag << '\n'
                                                    << input
                                                    << gg_tasm.DASM(instruction) << " [" << instruction
                                                    << "]" << '\n'
                                                    << Diagnose(local_cpu, arm, errFlag);

                        CpuPC_ResetThumb(arm, local_cpu);
                        ++t;
                    } // for
                } // for
            };

            task();
            fmt::print("[{}] Op: {:#x} {}\n", std::this_thread::get_id(), Op, t);
            return t;
        };

        for (int OpTest = 0; OpTest < 3; ++OpTest) {
            for (int RsTest = 0; RsTest < 16; ++RsTest) {
                for (int RdTest = 0; RdTest < 16; ++RdTest) {
                    for (int hibit = 0b01; hibit <= 0b11; ++hibit) {
                        uint32_t RsValue = 0x01010101 * RsTest;
                        uint32_t RdValue = 0x01010101 * RdTest;
                        TestMain(OpTest, true, false, RsValue, RdValue);
                    } // for
                } // for
            } // for
        } // for
    }

    TEST_F(ggTest, Thumb_BX) {
        auto TestMain = [&](const unsigned Op, bool HiRd, bool HiRs, const uint32_t RsValue,
                            const uint32_t RdValue) -> uint64_t {
            uint64_t t = 0;

            arm.cpsr.t = true ; // for thumb ReadUnused()
            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
            GgInitToThumbState(local_cpu);

            CpuPC_ResetThumb(arm, local_cpu);

            const int RdStart = HiRd ? 8 : 0;
            const int RsStart = HiRs ? 8 : 0;

            auto task = [&]() {
                for (int RsNum = RsStart; RsNum < RsStart + 8; ++RsNum) {
                    uint16_t instruction =
                            (0b010001 << 10) | (Op << 8) | (HiRd << 7) | (HiRs << 6) | ((RsNum - RsStart) << 3) | 0;

                    arm.regs[RsNum] = RsValue;
                    local_cpu._regs[RsNum] = RsValue;

                    EggRunThumb(arm, instruction);
                    local_cpu.CPU_Test(instruction);

                    uint32_t errFlag = CheckStatus(local_cpu, arm);
                    std::string input = fmt::format("Original Rs(R{}): {:#x}\n",
                                                    RdValue, RsNum, RsValue);

                    Type5CalleeCheek(local_cpu, Op, HiRd, HiRs);

                    ASSERT_TRUE(errFlag == 0)
                                                << "#" << t << " of test\n"
                                                << std::hex << "Errflag: " << errFlag << '\n'
                                                << input
                                                << gg_tasm.DASM(instruction) << " [" << instruction
                                                << "]" << '\n'
                                                << Diagnose(local_cpu, arm, errFlag);

                    CpuPC_ResetThumb(arm, local_cpu);
                    ++t;
                } // for
            };

            task();
            fmt::print("[{}] Op: BX, dstAddr: {:#x}, total_t: {}\n", std::this_thread::get_id(), RsValue, t);
            return t;
        };

        constexpr auto dstList = gg_core::make_array(
            0x0, // in bios
            0x2000000, // start of EWRAM,
            0x2000001, // start of EWRAM, change to thumb mode
            0x203ffff, // end of EWRAM, test for out of bound access
            0x3000000, // start of IWRAM
            0x3007fff, // end of IWRAM, test for out of bound access
            0x8000000, // ROM area(WS0)
            0xA000002, // ROM area(WS1)
            0xC000004, // ROM area(WS2)
            0x10000000 // Unused area
        ) ;

        for (auto dstAddr : dstList) {
            TestMain(0b11, false, false, dstAddr, 0);
            TestMain(0b11, false, true, dstAddr, 0);
        } // for
    }
}

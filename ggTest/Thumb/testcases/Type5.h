//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;
    void CalleeCheek(CPU& local_cpu, const unsigned Op, const bool H1, const bool H2) {
        const int hashcode = (Op << 2) | (H1 << 1) | H2 ;
        switch (hashcode) {
            case 0b0001:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<ADD, false, true>) ;
                break ;
            case 0b0010:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<ADD, true, false>) ;
                break ;
            case 0b0011:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<ADD, true, true>) ;
                break ;

            case 0b0101:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<CMP, false, true>) ;
                break ;
            case 0b0110:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<CMP, true, false>) ;
                break ;
            case 0b0111:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<CMP, true, true>) ;
                break ;

            case 0b1001:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<MOV, false, true>) ;
                break ;
            case 0b1010:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<MOV, true, false>) ;
                break ;
            case 0b1011:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<MOV, true, true>) ;
                break ;

            case 0b1100:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<0, false, false>) ;
                break ;
            case 0b1101:
                ASSERT_TRUE(local_cpu.lastCallee == HiRegOperation_BX<0, false, true>) ;
                break ;
            default:
                throw std::logic_error("Invalid Op number") ;
        } // switch
    } // Op2Shift()

    TEST_F(ggTest, ALU_Operation) {
        auto TestMain = [&](const unsigned Op, bool HiRd, bool HiRs, const uint32_t RsValue, const uint32_t RdValue) -> uint64_t {
            uint64_t t = 0;

            Arm egg_local;
            egg_local.flushHalf();
            egg_local.cpsr.t = true;

            gg_core::GbaInstance instance_local;
            gg_core::gg_cpu::CPU &local_cpu = instance_local.cpu;
            GgInitToThumbState(local_cpu);

            const int RdStart = HiRd ? 0 : 8 ;
            const int RsStart = HiRs ? 0 : 8 ;

            auto task = [&]() {
                for (int RsNum = RsStart; RsNum < RsStart + 8; ++RsNum) {
                    for (int RdNum = RdStart; RdNum < RdStart + 8; ++RdNum) {
                        uint16_t instruction = (0b010001 << 10) | (Op << 8) | (HiRd << 7) | (HiRs << 6) | (RsNum << 3) | RdNum;

                        egg_local.regs[RsNum] = RsValue;
                        local_cpu._regs[RsNum] = RsValue;

                        egg_local.regs[RdNum] = RdValue;
                        local_cpu._regs[RdNum] = RdValue;

                        EggRunThumb(egg_local, instruction);
                        local_cpu.CPU_Test(instruction);

                        uint32_t errFlag = CheckStatus(local_cpu, egg_local);
                        std::string input = fmt::format("Original Rd(R{}): {:#x} Rs(R{}): {:#x}\n",
                                                        RdNum, RdValue, RsNum, RsValue);

                        CalleeCheek(local_cpu, Op);

                        ASSERT_TRUE(errFlag == 0)
                                                    << "#" << t << " of test\n"
                                                    << std::hex << "Errflag: " << errFlag << '\n'
                                                    << input
                                                    << gg_tasm.DASM(instruction) << " [" << instruction
                                                    << "]" << '\n'
                                                    << Diagnose(local_cpu, egg_local, errFlag);

                        CpuPC_Reset(egg_local, local_cpu);
                        ++t;
                    } // for
                } // for
            };

            task();
            fmt::print("[{}] Rd: {:#x} {}\n", std::this_thread::get_id(), Op, t);
            return t;
        };

        boost::asio::thread_pool workerPool(std::thread::hardware_concurrency());
        for (int OpTest = 0; OpTest < 4 ; ++OpTest) {
            for (int RsTest = 0; RsTest < 16; ++RsTest) {
                for (int RdTest = 0; RdTest < 16; ++RdTest) {

                    if (OpTest == 0b11) {
                        // BX Test
//                        boost::asio::post(workerPool,
//                                          [TestMain, OpTest, RsValue, RdValue] {
//                                              return TestMain(OpTest, false, false, RsValue, RdValue);
//                                          } // lambda
//                        );
                    } // if
                    else {
                        for (int hibit = 0b01 ; hibit <= 0b11 ; ++hibit) {
                            uint32_t RsValue = 0x01010101 * RsTest;
                            uint32_t RdValue = 0x01010101 * RdTest;

                            boost::asio::post(workerPool,
                                [TestMain, OpTest, RsValue, RdValue, hibit] {
                                    return TestMain(OpTest, hibit & 0b10, hibit & 0b01, RsValue, RdValue);
                                } // lambda
                            );

                            if (RsValue != 0) {
                                boost::asio::post(workerPool,
                                    [TestMain, OpTest, RsValue, RdValue, hibit] {
                                        return TestMain(OpTest, hibit & 0b10, hibit & 0b01, RsValue << 4, RdValue);
                                        } // lambda
                                );
                            } // if

                            if (RdValue != 0) {
                                boost::asio::post(workerPool,
                                                  [TestMain, OpTest, RsValue, RdValue, hibit] {
                                                      return TestMain(OpTest, hibit & 0b10, hibit & 0b01, RsValue, RdValue << 4);
                                                  } // lambda
                                );
                            } // if

                            if (RdValue != 0 && RsValue != 0) {
                                boost::asio::post(workerPool,
                                                  [TestMain, OpTest, RsValue, RdValue, hibit] {
                                                      return TestMain(OpTest, hibit & 0b10, hibit & 0b01, RsValue << 4, RdValue << 4);
                                                  } // lambda
                                );
                            } // if
                        } // for
                    } // else
                } // for
            } // for
        } // for

        workerPool.join();
    }
}

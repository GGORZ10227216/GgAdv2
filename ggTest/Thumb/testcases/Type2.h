//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    TEST_F(ggTest, AddSub) {
        const unsigned immBit = 10;
        const unsigned opBit = 9;
        const unsigned RnOffsetStartBit = 6;
        const unsigned RsStartBit = 3;

        auto TestMain = [&](uint32_t RnVal, uint32_t RsVal) -> uint64_t {
            uint64_t t = 0;

            Arm egg_local;
            egg_local.flushHalf();
            egg_local.cpsr.t = true;

            gg_core::GbaInstance instance_local(testRomPath);
            gg_core::gg_cpu::CPU &local_cpu = instance_local.cpu;
            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int I = 0; I < 2; ++I) {
                    for (int Op = 0; Op < 2; ++Op) {
                        for (int RnOffset = 0; RnOffset < 8; ++RnOffset) {
                            if (!I) {
                                egg_local.regs[RnOffset] = RnVal;
                                local_cpu._regs[RnOffset] = RnVal;
                            } // if

                            for (int RsNum = 0; RsNum < 8; ++RsNum) {
                                egg_local.regs[RsNum] = RsVal;
                                local_cpu._regs[RsNum] = RsVal;

                                for (int RdNum = 0; RdNum < 8; ++RdNum) {
                                    uint16_t instruction = (0b00011 << 11) |
                                            (I << immBit) | (Op << opBit) | (RnOffset << RnOffsetStartBit) | (RsNum << RsStartBit) |
                                            RdNum;

                                    EggRunThumb(egg_local, instruction);
                                    local_cpu.CPU_Test(instruction);
                                    ++t;

                                    uint32_t errFlag = CheckStatus(local_cpu, egg_local);
                                    std::string input ;
                                    if (I)
                                        input = fmt::format("Rs(R{}): {:#x}\n", RsNum, RsVal) ;
                                    else
                                        input = fmt::format("Rs(R{}): {:#x}, Rn(R{}): {:#x}", RsNum, RsVal, RnOffset, RnVal);

                                    ASSERT_TRUE(errFlag == 0)
                                                                << "#" << t << " of test\n"
                                                                << std::hex << "Errflag: " << errFlag << '\n'
                                                                << input
                                                                << gg_tasm.DASM(instruction) << " [" << instruction
                                                                << "]" << '\n'
                                                                << Diagnose(local_cpu, egg_local, errFlag);

                                    CpuPC_Reset(egg_local, local_cpu);
                                }
                            }
                        }
                    }
                } // for
            };

            task();
            fmt::print("[{}] {}\n", std::this_thread::get_id(), t) ;
            return t ;
        };

        boost::asio::thread_pool workerPool(1) ;
        for (int RsTest = 0 ; RsTest < 1 ; ++RsTest) {
            for (int RnTest = 0 ; RnTest < 1 ; ++RnTest) {
                uint32_t rs_val = 0x01010101 * RsTest ;
                uint32_t rn_val = 0x01010101 * RnTest ;

                boost::asio::post(workerPool, [TestMain, rs_val, rn_val] { return TestMain(rs_val << 4, rn_val << 4); }) ;
            } // for
        } // for

        workerPool.join();
    }
}
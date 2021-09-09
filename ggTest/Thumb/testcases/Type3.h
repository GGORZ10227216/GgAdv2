//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    TEST_F(ggTest, MovCmpAddSub) {
        auto TestMain = [&](const unsigned Op, const uint32_t originalRdVal) -> uint64_t {
            uint64_t t = 0;

            Arm egg_local;
            egg_local.flushHalf();
            egg_local.cpsr.t = true;

            gg_core::GbaInstance instance_local;
            gg_core::gg_cpu::CPU &local_cpu = instance_local.cpu;
            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                    for (int offset8 = 0 ; offset8 <= 0xff ; ++offset8) {
                        uint16_t instruction = (0b001 << 13) | (Op << 11) | (RdNum << 8) | offset8 ;

                        egg_local.regs[ RdNum ] = originalRdVal ;
                        local_cpu._regs[ RdNum ] = originalRdVal ;

                        EggRunThumb(egg_local, instruction);
                        local_cpu.CPU_Test(instruction);
                        ++t;

                        uint32_t errFlag = CheckStatus(local_cpu, egg_local);
                        std::string input = fmt::format("Original Rd(R{}): {:#x}\n", RdNum, originalRdVal) ;

                        ASSERT_TRUE(errFlag == 0)
                                                    << "#" << t << " of test\n"
                                                    << std::hex << "Errflag: " << errFlag << '\n'
                                                    << input
                                                    << gg_tasm.DASM(instruction) << " [" << instruction
                                                    << "]" << '\n'
                                                    << Diagnose(local_cpu, egg_local, errFlag);

                        CpuPC_Reset(egg_local, local_cpu);
                    } // for
                } // for
            };

            task();
            fmt::print("[{}] Rd: {:#x} {}\n", std::this_thread::get_id(), originalRdVal, t) ;
            return t ;
        };

        boost::asio::thread_pool workerPool(std::thread::hardware_concurrency()) ;
        for (int OpTest = 0 ; OpTest < 4 ; ++OpTest) {
            for (int RdTest = 0 ; RdTest < 16 ; ++RdTest) {
                uint32_t test = 0x01010101 * RdTest ;
                boost::asio::post(workerPool, [TestMain, OpTest, test] { return TestMain(OpTest, test); }) ;
                if (test != 0)
                    boost::asio::post(workerPool, [TestMain, OpTest, test] { return TestMain(OpTest, test << 4); }) ;
            } // for
        } // for

        workerPool.join();
    }
}
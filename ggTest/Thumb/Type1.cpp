//
// Created by Jason4_Lee on 2021-08-24.
//

#include <gg_test.h>

namespace {
    TEST_F(ggTest, thumb_move_shift_reg) {
        const unsigned OpStartBit = 11 ;
        const unsigned Offset5StartBit = 6 ;
        const unsigned RsStartBit = 3 ;
        const unsigned RdStartBit = 0 ;

        auto TestMain = [&](int srcRegVal) -> uint64_t {
            uint64_t t = 0 ;

            Arm egg_local ;
            egg_local.flushHalf() ;
            egg_local.cpsr.t = true ;

            gg_core::GbaInstance instance_local(testRomPath) ;
            gg_core::gg_cpu::CPU& local_cpu = instance_local.cpu;
            GgInitToThumbState(local_cpu) ;

            uint32_t errFlag = CheckStatus(local_cpu, egg_local);

            auto task = [&]() {
                for (int Op = 0 ; Op < 3 ; ++Op) {
                    for (int Offset5 = 0 ; Offset5 < 32 ; ++Offset5) {
                        for (int RsNum = 0 ; RsNum < 8 ; ++RsNum) {
                            egg_local.regs[ RsNum ] = srcRegVal ;
                            local_cpu._regs[ RsNum ] = srcRegVal ;
                            for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                                uint16_t instruction = (Op << OpStartBit) | (Offset5 << Offset5StartBit) | (RsNum << RsStartBit) | (RdNum << RdStartBit) ;

                                EggRunThumb(egg_local, instruction) ;
                                local_cpu.CPU_Test(instruction) ;
                                ++t ;

                                uint32_t errFlag = CheckStatus(local_cpu, egg_local);
                                ASSERT_TRUE(errFlag == 0)
                                                            << "#" << t << " of test\n"
                                                            << std::hex << "Errflag: " << errFlag << '\n'
                                                            << fmt::format("R{}: {:#x}\n", RsNum, srcRegVal)
                                                            << gg_tasm.DASM(instruction) << " [" << instruction << "]" << '\n' << Diagnose(local_cpu, egg_local, errFlag);

                                CpuPC_Reset(egg_local, local_cpu);
                            }}}} // for
            };

            task() ;
            return t ;
        };

        std::vector<WorkerResult2<unsigned int, decltype(std::async(std::launch::async, TestMain, 0))>> workers;
        for (int part = 0 ; part < 16 ; ++part) {
            unsigned int val = part * 0x01010101 ;
            auto result = std::make_pair(val,std::async(std::launch::async, TestMain, val));
            workers.push_back(std::move(result));

            if (val != 0) {
                auto result2 = std::make_pair(val << 4,std::async(std::launch::async, TestMain, val << 4));
                workers.push_back(std::move(result2));
            } // if
        } // for

        for (auto &t : workers)
            fmt::print("[{:#x}] Total performed tests: {}\n", t.first, t.second.get());
    }
}
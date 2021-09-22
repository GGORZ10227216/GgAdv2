//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, PC_RelativeLoad) {
        auto TestMain = [&](int Word8) -> uint64_t {
            uint64_t t = 0;

            arm.flushHalf();
            arm.cpsr.t = true;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
            GgInitToThumbState(local_cpu);

            for (int i = 0 ; i < 0x40000 ; ++i) {
                gbaInstance.mmu.Write<uint8_t>(0x2000000+i, static_cast<uint8_t>(i), S_Cycle) ;
                arm.writeByte(0x2000000+i, static_cast<uint8_t>(i));
            } // for

            auto task = [&]() {
                for (int RdNum = 0; RdNum < 8; ++RdNum) {
                    uint16_t instruction = (0b01001 << 11) | (RdNum << 8) | Word8;

                    arm.regs[pc] = 0x2000000;
                    local_cpu._regs[pc] = 0x2000000;

                    EggRunThumb(arm, instruction);
                    local_cpu.CPU_Test(instruction);

                    uint32_t errFlag = CheckStatus(local_cpu, arm);
                    std::string input = fmt::format("Word8: {:#x}\n", Word8);

                    ASSERT_TRUE((local_cpu.lastCallee == PC_RelativeLoad));
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
            };

            task();
            fmt::print("[{}] Word8: {:#x} total_t: {}\n", std::this_thread::get_id(), Word8, t);
            return t;
        };

        for (int word = 0; word < 0xff ; ++word)
            TestMain(word);
    }
}

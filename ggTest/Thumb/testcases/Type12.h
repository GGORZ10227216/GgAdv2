//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, Thumb_load_addr_of_sp){
        auto TestMain = [&]() -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int offset = 0 ; offset < 0x100 ; ++offset) {
                    for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                        uint16_t instruction = (0b1010 << 12)|(1 << 11)|(RdNum << 8)|offset;

                        arm.regs[sp] = gg_core::rotr(0x12345678, offset) ;
                        local_cpu._regs[sp] = gg_core::rotr(0x12345678, offset) ;
                        std::string input = fmt::format("SP Value: {:#x}, Offset value: {:#x}\n",
                                                        local_cpu._regs[sp], offset << 2);

                        EggRunThumb(arm, instruction);
                        local_cpu.CPU_Test(instruction);

                        uint32_t errFlag = CheckStatus(local_cpu, arm);

                        ASSERT_TRUE((local_cpu.lastCallee == LoadAddress<true>));
                        ASSERT_TRUE((gbaInstance.mmu.bios_readBuf == mmu.bios.previous));
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
            };

            task();
            return t;
        };

        TestMain() ;
    }

    TEST_F(ggTest, Thumb_load_addr_of_pc){
        auto TestMain = [&]() -> uint64_t {
            uint64_t t = 0;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;

            arm.cpsr.t = true;
            arm.flushHalf();

            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int offset = 0 ; offset < 0x100 ; ++offset) {
                    for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                        uint16_t instruction = (0b1010 << 12)|(RdNum << 8)|offset;

                        arm.regs[pc] = gg_core::rotr(0x12345678, offset) ;
                        local_cpu._regs[pc] = gg_core::rotr(0x12345678, offset) ;
                        std::string input = fmt::format("PC Value: {:#x}, Offset value: {:#x}\n",
                                                        local_cpu._regs[pc], offset << 2);

                        EggRunThumb(arm, instruction);
                        local_cpu.CPU_Test(instruction);

                        uint32_t errFlag = CheckStatus(local_cpu, arm);

                        ASSERT_TRUE((local_cpu.lastCallee == LoadAddress<false>));
                        ASSERT_TRUE((gbaInstance.mmu.bios_readBuf == mmu.bios.previous));
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
            };

            task();
            return t;
        };

        TestMain() ;
    }
}

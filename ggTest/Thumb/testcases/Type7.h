//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, Thumb_load_with_reg_offset) {
        auto TestMain = [&](uint32_t RbValue, uint32_t RoValue, uint32_t areaBound) -> uint64_t {
            uint64_t t = 0;

            arm.regs[pc] = 0 ;
            arm.flushHalf();
            arm.cpsr.t = true;

            gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
            GgInitToThumbState(local_cpu);

            auto task = [&]() {
                for (int RbNum = 0; RbNum < 8; ++RbNum) {
                    for (int RoNum = 0 ; RoNum < 8 ; ++RoNum) {
                        for (int RdNum = 0 ; RdNum < 8 ; ++RdNum) {
                            if (RdNum == RbNum || RdNum == RoNum)
                                continue;

                            uint16_t instruction = (0b0101 << 12)|(0b10 << 10)|(RoNum << 6)|(RbNum << 3)|RdNum;

                            arm.regs[RbNum] = RbValue;
                            local_cpu._regs[RbNum] = RbValue;

                            arm.regs[RoNum] = RoValue;
                            local_cpu._regs[RoNum] = RoValue;

                            uint32_t targetDst = local_cpu._regs[RbNum] + local_cpu._regs[RoNum] ;
                            if (targetDst < RbValue || targetDst >= areaBound)
                                continue;

                            EggRunThumb(arm, instruction);
                            local_cpu.CPU_Test(instruction);

                            uint32_t errFlag = CheckStatus(local_cpu, arm);
                            std::string input = fmt::format("Base RegValue: {:#x}, Offset RegValue: {:#x}\n",
                                                            RbValue, RoValue);

                            ASSERT_TRUE((local_cpu.lastCallee == LoadStoreRegOffset<true, false>));
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
//            fmt::print("[{}] LDR base: {:#x} offset: {:#x} total_t: {}\n", std::this_thread::get_id(), RbValue, RoValue, t);
            return t;
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
            std::make_tuple(gg_mem::BIOS_start, E_BIOS_SIZE, gg_mem::onboardStart)
//            std::make_pair(gg_mem::onboardStart, E_EWRAM_SIZE),
//            std::make_tuple(gg_mem::onchipStart, E_IWRAM_SIZE, gg_mem::ioStart),
//            std::make_pair(gg_mem::paletteStart, E_PALETTE_SIZE),
//            std::make_pair(gg_mem::VRAM_Start, E_VRAM_SIZE),
//            std::make_pair(gg_mem::OAM_Start, E_OAM_SIZE),
//            std::make_pair(gg_mem::WAITSTATE_0_Start, E_ROM_BLOCK_SIZE),
//            std::make_pair(gg_mem::WAITSTATE_1_Start, E_ROM_BLOCK_SIZE),
//            std::make_pair(gg_mem::WAITSTATE_2_Start, E_ROM_BLOCK_SIZE)
        ) ;

        int i = 0 ;
        for (const auto& areaInfo : areaList) {
            auto [base, vaildAccessOffset, bound] = areaInfo ;

            if (base != 0) {
                for (int i = base ; i < vaildAccessOffset; ++i) {
                    gbaInstance.mmu.Write<uint8_t>(base+i, static_cast<uint8_t>(i), S_Cycle) ;
                    arm.writeByte(base+i, static_cast<uint8_t>(i));
                } // for
            } // if

//            for (int currentOffset = 0 ; currentOffset < bound; ++currentOffset) {
//                TestMain(base, currentOffset, bound) ;
//                i++ ;
//            } // for
            TestMain(0x0, 0x800000, bound) ;
        } // for
    }
}

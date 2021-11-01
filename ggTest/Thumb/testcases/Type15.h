//
// Created by Jason4_Lee on 2021-08-24.
//

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, Thumb_stmia){
        int t = 0 ;
        gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
        arm.cpsr.t = true;
        arm.flushHalf();

        GgInitToThumbState(local_cpu);

        auto task = [&](uint32_t baseAddr) {
            int Rlist = 0 ;
            for (Rlist = 0 ; Rlist <= 0xff ; ++Rlist) {
                for (int i = 0, j = 0 ; i < 8 ; ++i) {
                    if (gg_core::TestBit(Rlist, i)) {
                        arm.regs[ i ] = testData[ j ] ;
                        local_cpu._regs[ i ] = testData[ j ] ;
                        ++j;
                    } // if
                } // for

                for (int RbNum = 0 ; RbNum < 8 ; ++RbNum) {
                    uint32_t instruction = (0b1100 << 12) | (RbNum << 8) | Rlist;

                    arm.regs[pc] = baseAddr ;
                    local_cpu._regs[pc] = baseAddr ;

                    arm.regs[RbNum] = baseAddr ;
                    local_cpu._regs[RbNum] = baseAddr ;

                    std::string input = fmt::format("baseReg Value: {:#x}, Rlist: {:#x}\n", baseAddr, Rlist);

                    EggRunThumb(arm, instruction);
                    local_cpu.CPU_Test(instruction);

                    uint32_t errFlag = CheckStatus(local_cpu, arm);

                    ASSERT_TRUE((local_cpu.lastCallee == MultiLoadStore<false>));

                    if (Rlist != 0) {
                        for (int i = 0, j = 0 ; i < 8 ; ++i) {
                            if (gg_core::TestBit(Rlist, i)) {
                                const uint32_t refReadback = arm.readWordRotate((baseAddr + j*4) & ~0x3);
                                const uint32_t ggReadback = gbaInstance.mmu.Read<uint32_t>((baseAddr + j*4) & ~0x3, gg_core::gg_mem::S_Cycle) ;

                                if (i == RbNum && i == __builtin_ctz(Rlist))
                                    ASSERT_TRUE(arm.regs[ i ] - (gg_core::PopCount32(Rlist) << 2) == refReadback);
                                else
                                    ASSERT_TRUE(arm.regs[ i ] == refReadback);

                                ASSERT_TRUE(ggReadback == refReadback);

                                ++j ;
                            } // if
                        } // for
                    } // if
                    else {
                        const uint32_t refReadback = arm.readWordRotate(baseAddr & ~0x3) ;
                        const uint32_t ggReadback = gbaInstance.mmu.Read<uint32_t>(baseAddr & ~0x3, gg_core::gg_mem::S_Cycle) ;

                        ASSERT_TRUE(arm.regs[ pc ] + 2 == refReadback);
                        ASSERT_TRUE(ggReadback == refReadback);
                    } // else


                    ASSERT_TRUE(errFlag == 0)
                                                << "#" << t << " of test\n"
                                                << std::hex << "Errflag: " << errFlag << '\n'
                                                << input
                                                << gg_tasm.DASM(instruction) << " [" << instruction
                                                << "]" << '\n'
                                                << Diagnose(local_cpu, arm, errFlag);

                    CpuPC_Reset(arm, local_cpu);
                    ++t ;
                } // for
            } // for
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
                0x03007f00,
                0x03007f01,
                0x03007f02,
                0x03007f03
        ) ;

        for (const auto base : areaList)
            task(base) ;
    }

    TEST_F(ggTest, Thumb_ldmia){
        int t = 0 ;
        gg_core::gg_cpu::CPU &local_cpu = gbaInstance.cpu;
        arm.cpsr.t = true;
        arm.flushHalf();

        GgInitToThumbState(local_cpu);

        for (int idx = 0x0300'0000, j = 0 ; idx < gg_core::gg_mem::onchipEnd ; idx += 4) {
            arm.writeWord(idx, testData[j]);
            gbaInstance.mmu.Write<uint32_t>(idx, testData[j], gg_core::gg_mem::S_Cycle);
            j = (j+1) % testData.size();
        } // for

        auto task = [&](uint32_t baseAddr) {
            int Rlist = 0 ;
            for (Rlist = 0 ; Rlist <= 0xff ; ++Rlist) {
                for (int i = 0, j = 0 ; i < 8 ; ++i) {
                    if (gg_core::TestBit(Rlist, i)) {
                        arm.regs[ i ] = testData[ j ] ;
                        local_cpu._regs[ i ] = testData[ j ] ;
                        ++j;
                    } // if
                } // for

                for (int RbNum = 0 ; RbNum < 8 ; ++RbNum) {
                    uint32_t instruction = (0b11001 << 11) | (RbNum << 8) | Rlist ;

                    arm.regs[RbNum] = baseAddr ;
                    local_cpu._regs[RbNum] = baseAddr ;

                    std::string input = fmt::format("baseReg Value: {:#x}, Rlist: {:#x}\n", baseAddr, Rlist);

                    EggRunThumb(arm, instruction);
                    local_cpu.CPU_Test(instruction);

                    uint32_t errFlag = CheckStatus(local_cpu, arm);

                    ASSERT_TRUE((local_cpu.lastCallee == MultiLoadStore<true>));

                    ASSERT_TRUE(errFlag == 0)
                                                << "#" << t << " of test\n"
                                                << std::hex << "Errflag: " << errFlag << '\n'
                                                << input
                                                << gg_tasm.DASM(instruction) << " [" << instruction
                                                << "]" << '\n'
                                                << Diagnose(local_cpu, arm, errFlag);

                    CpuPC_Reset(arm, local_cpu);
                    ++t ;
                } // for
            } // for
        };

        using namespace gg_core;
        const auto areaList = gg_core::make_array(
                0x03007f00,
                0x03007f01,
                0x03007f02,
                0x03007f03
        ) ;

        for (const auto base : areaList)
            task(base) ;
    }
}

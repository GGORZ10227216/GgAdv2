//
// Created by orzgg on 2021-01-31.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu ;
    using namespace gg_core::gg_mem ;

    const uint32_t baseAddr = 0x0201fef0 ;

    TEST_F(ggTest, stmib_test) {
        uint32_t t = 0 ;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        TestField wFlag(0,1,1) ;
        TestField regList(0, 0xffff, 1) ;
        E_RegName targetRn = r4 ;

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            for (unsigned i = 0 ; i < 16 ; ++i) {
                egg.regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28);
                instance._regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28) ;
            } // for

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, true, true, false, wFlag.value, false, r4, regList.value
            ) ;

            egg.regs[ r4 ] = baseAddr ; // OWRAM
            instance._regs[ r4 ] = baseAddr ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            for (unsigned i = 0, offsetCnt = 1; i < 16 ; ++i) {
                if (TestBit(regList.value, i)) {
                    uint32_t targetAddr = baseAddr + offsetCnt*4 ;
                    uint32_t mine = instance._mem.Read32(targetAddr) ;
                    uint32_t ref = egg.readWordRotate(targetAddr) ;

                    ASSERT_TRUE(mine == ref && mine != 0)
                        << "#" << t << std::endl
                        << "MemChk failed at r" << i
                        << " (read from 0x" << std::hex << targetAddr << ")" << std::endl
                        << "Mine: " << std::hex << mine << ", ref: " << ref << std::endl ;
                    ++offsetCnt ;
                } // if
            } // for

            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, stmia_test) {
        uint32_t t = 0 ;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        TestField wFlag(0,1,1) ;
        TestField regList(0, 0xffff, 1) ;
        E_RegName targetRn = r4 ;

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            for (unsigned i = 0 ; i < 16 ; ++i) {
                egg.regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28);
                instance._regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28) ;
            } // for

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, false, true, false, wFlag.value, false, r4, regList.value
            ) ;

            egg.regs[ r4 ] = baseAddr ; // OWRAM
            instance._regs[ r4 ] = baseAddr ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            for (unsigned i = 0, offsetCnt = 0; i < 16 ; ++i) {
                if (TestBit(regList.value, i)) {
                    uint32_t targetAddr = baseAddr + offsetCnt*4 ;
                    uint32_t mine = instance._mem.Read32(targetAddr) ;
                    uint32_t ref = egg.readWordRotate(targetAddr) ;

                    ASSERT_TRUE(mine == ref && mine != 0)
                                                << "#" << t << std::endl
                                                << "MemChk failed at r" << i
                                                << " (read from 0x" << std::hex << targetAddr << ")" << std::endl
                                                << "Mine: " << std::hex << mine << ", ref: " << ref << std::endl ;
                    ++offsetCnt ;
                } // if
            } // for

            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, stmdb_test) {
        uint32_t t = 0 ;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        TestField wFlag(0,1,1) ;
        TestField regList(0, 0xffff, 1) ;
        E_RegName targetRn = r4 ;

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            for (unsigned i = 0 ; i < 16 ; ++i) {
                egg.regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28);
                instance._regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28) ;
            } // for

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, true, false, false, wFlag.value, false, r4, regList.value
            ) ;

            egg.regs[ r4 ] = baseAddr ; // OWRAM
            instance._regs[ r4 ] = baseAddr ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);

            uint32_t decrementBase = baseAddr - gg_core::PopCount32(static_cast<uint32_t>(regList.value)) * 4 ;

            for (unsigned i = 0, offsetCnt = 0; i < 16 ; ++i) {
                if (TestBit(regList.value, i)) {
                    uint32_t targetAddr = decrementBase + offsetCnt*4 ;
                    uint32_t mine = instance._mem.Read32(targetAddr) ;
                    uint32_t ref = egg.readWordRotate(targetAddr) ;

                    ASSERT_TRUE(mine == ref && mine != 0)
                        << "#" << t << std::endl
                        << "MemChk failed at r" << i
                        << " (read from 0x" << std::hex << targetAddr << ")" << std::endl
                        << "Mine: " << std::hex << mine << ", ref: " << ref << std::endl ;
                    ++offsetCnt ;
                } // if
            } // for

            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, stmda_test) {
        uint32_t t = 0 ;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        TestField wFlag(0,1,1) ;
        TestField regList(0, 0xffff, 1) ;
        E_RegName targetRn = r4 ;

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            for (unsigned i = 0 ; i < 16 ; ++i) {
                egg.regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28);
                instance._regs[ i ] = (i << 4) | (i << 12) | (i << 20) | (0xe << 28) ;
            } // for

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, false, false, false, wFlag.value, false, r4, regList.value
            ) ;

            egg.regs[ r4 ] = baseAddr ; // OWRAM
            instance._regs[ r4 ] = baseAddr ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);

            uint32_t decrementBase = baseAddr - gg_core::PopCount32(static_cast<uint32_t>(regList.value)) * 4 ;

            for (unsigned i = 0, offsetCnt = 1; i < 16 ; ++i) {
                if (TestBit(regList.value, i)) {
                    uint32_t targetAddr = decrementBase + offsetCnt*4 ;
                    uint32_t mine = instance._mem.Read32(targetAddr) ;
                    uint32_t ref = egg.readWordRotate(targetAddr) ;

                    ASSERT_TRUE(mine == ref && mine != 0)
                                                << "#" << t << std::endl
                                                << "MemChk failed at r" << i
                                                << " (read from 0x" << std::hex << targetAddr << ")" << std::endl
                                                << "Mine: " << std::hex << mine << ", ref: " << ref << std::endl ;
                    ++offsetCnt ;
                } // if
            } // for

            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }
}
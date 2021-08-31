//
// Created by buildmachine on 2021-01-28.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    TEST_F(ggTest, arm_ldmib_test) {
        // ldmib -> pre-increment load, [L,P,U] == [1,1,1]
        uint32_t t = 0 ;

        TestField wFlag(0,1,1) ;
        E_RegName targetRn = r4 ;
        TestField regList(0, 0xffff, 1) ;

        for (int i = 0x3000000 ; i <= 0x3007fff ; i += 4) {
            instance._mem.Write32(i, 0xabcdabcd + i) ;
            egg.writeWord(i, 0xabcdabcd + i) ;
        } // for

        for (int i = 0 ; i < 16 ; ++i) {
            instance._regs[ i ] = 0;
            egg.regs[ i ] = 0 ;
        } // for

        auto testMain = [&]() {
            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, true, true, false, wFlag.value, true, r4, regList.value
            ) ;

            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            egg.regs[ r4 ] = 0x03006ea0 ; // OWRAM
            instance._regs[ r4 ] = 0x03006ea0 ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0 )
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag);

            CpuPC_Reset(egg, instance);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_ldmia_test) {
        // ldmia -> post-increment load, [L,P,U] == [1,0,1]
        uint32_t t = 0 ;

        TestField wFlag(0,1,1) ;
        E_RegName targetRn = r4 ;
        TestField regList(0, 0xffff, 1) ;

        for (int i = 0x3000000 ; i <= 0x3007fff ; i += 4) {
            instance._mem.Write32(i, 0xabcdabcd + i) ;
            egg.writeWord(i, 0xabcdabcd + i) ;
        } // for

        for (int i = 0 ; i < 16 ; ++i) {
            instance._regs[ i ] = 0;
            egg.regs[ i ] = 0 ;
        } // for

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, false, true, false, wFlag.value, true, r4, regList.value
            ) ;

            egg.regs[ r4 ] = 0x03006ea0 ; // OWRAM
            instance._regs[ r4 ] = 0x03006ea0 ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0 )
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);

            CpuPC_Reset(egg, instance);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_ldmdb_test) {
        // ldmdb -> pre-decrement load, [L,P,U] == [1,1,0]
        uint32_t t = 0 ;

        TestField wFlag(0,1,1) ;
        E_RegName targetRn = r4 ;
        TestField regList(0, 0xffff, 1) ;

        for (int i = 0x3000000 ; i <= 0x3007fff ; i += 4) {
            instance._mem.Write32(i, 0xabcdabcd + i) ;
            egg.writeWord(i, 0xabcdabcd + i) ;
        } // for

        for (int i = 0 ; i < 16 ; ++i) {
            instance._regs[ i ] = 0;
            egg.regs[ i ] = 0 ;
        } // for

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, true, false, false, wFlag.value, true, r4, regList.value
            ) ;

            egg.regs[ r4 ] = 0x03006ea0 ; // OWRAM
            instance._regs[ r4 ] = 0x03006ea0 ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0 )
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);

            CpuPC_Reset(egg, instance);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_ldmda_test) {
        // ldmda -> post-decrement load, [L,P,U] == [1,0,0]
        uint32_t t = 0 ;

        TestField wFlag(0,1,1) ;
        E_RegName targetRn = r4 ;
        TestField regList(0, 0xffff, 1) ;

        for (int i = 0x3000000 ; i <= 0x3007fff ; i += 4) {
            instance._mem.Write32(i, 0xabcdabcd + i) ;
            egg.writeWord(i, 0xabcdabcd + i) ;
        } // for

        for (int i = 0 ; i < 16 ; ++i) {
            instance._regs[ i ] = 0;
            egg.regs[ i ] = 0 ;
        } // for

        auto testMain = [&]() {
            // just bypass undefined behavior first
            if (gg_core::TestBit(regList.value, r4) || regList.value == 0)
                return ;

            uint32_t instruction = MakeBlockTransferInstruction<Cond, P, U, S, W, L, Rn, RegList>(
                    AL, false, false, false, wFlag.value, true, r4, regList.value
            ) ;

            egg.regs[ r4 ] = 0x03006ea0 ; // OWRAM
            instance._regs[ r4 ] = 0x03006ea0 ; // OWRAM

            uint32_t inst_hash = hashArm(instruction);
            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            ASSERT_TRUE(errFlag == 0 )
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);

            CpuPC_Reset(egg, instance);
            t++;
        };

        TEST_LOOPS(testMain, regList, wFlag) ;
        std::cout << "Test performed: " << t << std::endl;
    }
}
//
// Created by orzgg on 2020-12-12.
//
#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, mul_cpsr_test) {
        using namespace gg_core ;

        Arm egg;
        egg.init();
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;

        TestField targetRd(0, 0xe, 1) ;
        TestField targetRs(0, 0xe, 1) ;
        TestField RsValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 0xffffffff, 0x11111111) ;
        TestField cpsr(0, 0xf, 1) ;

        auto TestMain = [&]() {
            ++t ;
            uint32_t instruction = MakeMULInstruction<Cond, A, S, Rd, Rn, Rs, Rm>(
                    AL, false, true, targetRd.value, r0, targetRs.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRs.value, targetRm.value) ;
            auto val = std::make_tuple(RsValue.value, RmValue.value);
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            egg.cpsr = (cpsr.value << 28) | 0xd3 ;
            instance.WriteCPSR(cpsr.value << 28 | 0xd3) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << fmt::format( "Testcase: Rs: {:x}, Rm: {:x}\n", RsValue.value, RmValue.value )
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, cpsr, RsValue, RmValue,targetRd, targetRs,targetRm) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, mul_test) {
        using namespace gg_core ;

        Arm egg;
egg.init();
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;

        TestField targetRd(0, 0xe, 1) ;
        TestField targetRs(0, 0xe, 1) ;
        TestField RsValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 0xffffffff, 0x11111111) ;

        auto TestMain = [&]() {
            ++t ;
            uint32_t instruction = MakeMULInstruction<Cond, A, S, Rd, Rn, Rs, Rm>(
                    AL, false, true, targetRd.value, r0, targetRs.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRs.value, targetRm.value) ;
            auto val = std::make_tuple(RsValue.value, RmValue.value);
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Testcase: Rs: {:x}, Rm: {:x}\n", RsValue.value, RmValue.value )
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, RsValue, RmValue,targetRd, targetRs,targetRm) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, mla_cpsr_test) {
        using namespace gg_core ;

        Arm egg;
egg.init();
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;

        TestField targetRd(0, 0xe, 1) ;
        TestField targetRn(0, 0xe, 1) ;
        TestField RnValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRs(0, 0xe, 1) ;
        TestField RsValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 0xffffffff, 0x11111111) ;
        TestField cpsr(0, 0xf, 1) ;

        auto TestMain = [&]() {
            ++t ;
            uint32_t instruction = MakeMULInstruction<Cond, A, S, Rd, Rn, Rs, Rm>(
                    AL, true, true, targetRd.value, targetRn.value, targetRs.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRn.value, targetRs.value, targetRm.value) ;
            auto val = std::make_tuple(RnValue.value, RsValue.value, RmValue.value);
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            egg.cpsr = (cpsr.value << 28) | 0xd3 ;
            instance.WriteCPSR(cpsr.value << 28 | 0xd3) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Testcase: Rn: {:x}, Rs: {:x}, Rm: {:x}\n",
                                                        RnValue.value, RsValue.value, RmValue.value )
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, cpsr, RnValue, RsValue, RmValue,targetRd, targetRn,targetRs,targetRm) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, mla_test) {
        using namespace gg_core ;

        Arm egg;
egg.init();
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;

        TestField targetRd(0, 0xe, 1) ;
        TestField targetRn(0, 0xe, 1) ;
        TestField RnValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRs(0, 0xe, 1) ;
        TestField RsValue(0, 0xffffffff, 0x11111111) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 0xffffffff, 0x11111111) ;

        auto TestMain = [&]() {
            ++t ;
            uint32_t instruction = MakeMULInstruction<Cond, A, S, Rd, Rn, Rs, Rm>(
                    AL, true, true, targetRd.value, targetRn.value, targetRs.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRn.value, targetRs.value, targetRm.value) ;
            auto val = std::make_tuple(RnValue.value, RsValue.value, RmValue.value);
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Testcase: Rn: {:x}, Rs: {:x}, Rm: {:x}\n",
                                                        RnValue.value, RsValue.value, RmValue.value )
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, RnValue, RsValue, RmValue,targetRd, targetRn,targetRs,targetRm) ;
        std::cout << "Test performed: " << t << std::endl ;
    }
}
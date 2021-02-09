//
// Created by buildmachine on 2020-12-22.
//

#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu;

    static constexpr std::array<uint32_t, 4> testValue {
        0xdeadbeef,
        0xa0b1c2d4,
        0x0c0011ab,
        0xffffffff
    };

    TEST_F(ggTest, swp_test) {
        using namespace gg_core;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        uint64_t t = 0 ;
        TestField targetRd(0, 0xe, 1) ;
        TestField targetRn(0, 0xe, 1) ;
        TestField RnValue(0x3000000, 0x3007fff, 1) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 3, 1) ;
        TestField memValue(0, 3, 1) ;

        auto TestMain = [&]() {
            ++ t ;
            if (targetRn.value == targetRm.value)
                return ;

            uint32_t instruction = MakeSwapInstruction<Cond, B, Rn, Rd, Rm>(
                    AL, false, targetRn.value, targetRd.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRn.value, targetRm.value) ;
            auto val = std::make_tuple(RnValue.value, testValue[ RmValue.value ] );
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            instance._mem.Write32((uint32_t)RnValue.value, testValue[ memValue.value ]) ;
            egg.writeWord((uint32_t)RnValue.value, testValue[ memValue.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                << "#" << t << " of test" << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << fmt::format( "Rn: {:x}, Rm: {:x}, mem: {:x}\n", RnValue.value, RmValue.value, memValue.value )
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag) ;
            ASSERT_TRUE(instance._mem.Read32(RnValue.value) == egg.readWordRotate(RnValue.value)) ;
        };

        TEST_LOOPS(TestMain, targetRd, targetRn, targetRm, RnValue, RmValue, memValue) ;
        fmt::print("Total performed tests: {}\n", t);
    }

    TEST_F(ggTest, swpb_test) {
        using namespace gg_core;

        Arm egg;
        gg_mem::MMU mmu(std::nullopt) ;
        CPU instance(mmu);
        ArmAssembler gg_asm;

        uint64_t t = 0 ;
        TestField targetRd(0, 0xe, 1) ;
        TestField targetRn(0, 0xe, 1) ;
        TestField RnValue(0x3000000, 0x3007fff, 1) ;
        TestField targetRm(0, 0xe, 1) ;
        TestField RmValue(0, 3, 1) ;
        TestField memValue(0, 3, 1) ;

        auto TestMain = [&]() {
            ++ t ;
            if (targetRn.value == targetRm.value)
                return ;

            uint32_t instruction = MakeSwapInstruction<Cond, B, Rn, Rd, Rm>(
                    AL, true, targetRn.value, targetRd.value, targetRm.value
            ) ;

            auto idx = std::make_tuple(targetRn.value, targetRm.value) ;
            auto val = std::make_tuple(RnValue.value, testValue[ RmValue.value ] );
            FillRegs(instance._regs, idx, val) ;
            FillRegs(egg.regs, idx, val) ;

            instance._mem.Write8((uint32_t)RnValue.value, (uint8_t)testValue[ memValue.value ]) ;
            egg.writeByte((uint32_t)RnValue.value, testValue[ memValue.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;

            bool memChk = instance._mem.Read8(RnValue.value) == egg.readByte(RnValue.value) ;

            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << " of test" << '\n'
                                        << "memory check:" << memChk << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Rn: {:x}, Rm: {:x}, mem: {:x}\n", RnValue.value, RmValue.value, memValue.value )
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, targetRd, targetRn, targetRm, RnValue, RmValue, memValue) ;
        fmt::print("Total performed tests: {}\n", t);
    }
}


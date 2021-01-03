//
// Created by orzgg on 2021-01-02.
//

#include <gg_test.h>

namespace {
    using namespace gg_core ;
    using namespace gg_core::gg_cpu ;
    using namespace gg_core::gg_mem ;

    const uint32_t baseAddr = 0x0201ff00 ;
    static constexpr std::array<uint32_t, 4> testValue {
            0xdeadbeef,
            0xa0b1c2d4,
            0x0c0011ab,
            0xffffffff
    };

    TEST_F(ggTest, ldr_post_imm_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;
        TestField immOffset(0, 0xfff, 1) ;
        TestField memValueidx(0, 3, 1) ;

        TestField uFlag(0, 1, 1) ;
        TestField wFlag(0, 1, 1) ;

        auto TestMain = [&]() {
            ++t ;

            if (wFlag.value && targetRn.value == pc)
                return ;

            uint32_t targetAddr = baseAddr ;
//            if (uFlag.value)
//                targetAddr += immOffset.value ;
//            else
//                targetAddr -= immOffset.value ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, false, wFlag.value, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUTick_Debug(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            uint32_t memReadBack = gg_core::rotr(testValue[memValueidx.value], (targetAddr & 0b11) << 3);
            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << fmt::format( "Testcase: offset: {:x}\n", immOffset.value)
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, immOffset, memValueidx) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldr_pre_imm_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xe, 1) ;
        TestField targetRd(0, 0xe, 1) ;
        TestField immOffset(0, 0xfff, 1) ;
        TestField memValueidx(0, 3, 1) ;

        TestField uFlag(0, 1, 1) ;
        TestField wFlag(0, 1, 1) ;

        auto TestMain = [&]() {
            ++t ;

            if (wFlag.value && targetRn.value == pc)
                return ;

            uint32_t targetAddr = baseAddr ;
//            if (uFlag.value)
//                targetAddr += immOffset.value ;
//            else
//                targetAddr -= immOffset.value ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, false, wFlag.value, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUTick_Debug(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            uint32_t memReadBack = gg_core::rotr(testValue[memValueidx.value], (targetAddr & 0b11) << 3);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, immOffset, memValueidx) ;
        std::cout << "Test performed: " << t << std::endl ;
    }
}
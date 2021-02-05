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

        auto TestMain = [&]() {
            ++t ;

            if (targetRn.value == pc)
                return ;

            uint32_t targetAddr = baseAddr ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, false, false, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            uint32_t memReadBack = gg_core::rotr(testValue[memValueidx.value], (targetAddr & 0b11) << 3);
            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << fmt::format( "Testcase: offset: {:x}\n", immOffset.value)
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag,targetRn, targetRd, immOffset, memValueidx) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldr_post_reg_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;

        TestField shiftType(0, 3, 1) ;
        TestField shiftAmount(0, 0x1f, 1) ;
        TestField RmValue(0, 0xff, 1) ;

        TestField uFlag(0, 1, 1) ;

        for (int i = 0x2000000, j = 0 ; i <= 0x203ffff ; i += 4) {
            instance._mem.Write32(i, testValue[ j ]) ;
            egg.writeWord(i, testValue[ j ]) ;

            j = (j + 1) & 0b11 ;
        } // for

        auto TestMain = [&]() {
            ++t ;

            if (targetRn.value == pc)
                return ;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return ;

            uint32_t offset = RmValue.value ;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value ;
                    break;
                case LSR:
                    offset >>= shiftAmount.value ;
                    break ;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value ;
                    break ;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break ;
            }

            if (uFlag.value && (baseAddr + offset < 0x2000000 || baseAddr + offset > 0x203ffff))
                return ;
            if (!uFlag.value && (baseAddr - offset < 0x2000000 || baseAddr - offset > 0x203ffff))
                return ;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, false, uFlag.value, false, false, true,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._status._regs[ r4 ] = RmValue.value ;
            egg.regs[ r4 ] = RmValue.value ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag,targetRn, targetRd, shiftType, shiftAmount, RmValue) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldrb_post_imm_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;
        TestField immOffset(0, 0xfff, 1) ;
        TestField memValueidx(0, 3, 1) ;

        TestField uFlag(0, 1, 1) ;

        auto TestMain = [&]() {
            ++t ;

            if (targetRn.value == pc)
                return ;

            uint32_t targetAddr = baseAddr ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, true, false, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            uint32_t memReadBack = gg_core::rotr(testValue[memValueidx.value], (targetAddr & 0b11) << 3);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format( "Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, immOffset, memValueidx) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldrb_post_reg_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;

        TestField shiftType(0, 3, 1) ;
        TestField shiftAmount(0, 0x1f, 1) ;
        TestField RmValue(0, 0xff, 1) ;

        TestField uFlag(0, 1, 1) ;

        for (int i = 0x2000000, j = 0 ; i <= 0x203ffff ; i += 4) {
            instance._mem.Write32(i, testValue[ j ]) ;
            egg.writeWord(i, testValue[ j ]) ;

            j = (j + 1) & 0b11 ;
        } // for

        auto TestMain = [&]() {
            ++t ;

            if (targetRn.value == pc)
                return ;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return ;

            uint32_t offset = RmValue.value ;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value ;
                    break;
                case LSR:
                    offset >>= shiftAmount.value ;
                    break ;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value ;
                    break ;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break ;
            }

            if (uFlag.value && (baseAddr + offset < 0x2000000 || baseAddr + offset > 0x203ffff))
                return ;
            if (!uFlag.value && (baseAddr - offset < 0x2000000 || baseAddr - offset > 0x203ffff))
                return ;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, false, uFlag.value, true, false, true,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._status._regs[ r4 ] = RmValue.value ;
            egg.regs[ r4 ] = RmValue.value ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldr_pre_imm_offset_test) {
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
            if (uFlag.value)
                targetAddr += immOffset.value ;
            else
                targetAddr -= immOffset.value ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, true, uFlag.value, false, wFlag.value, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

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

    TEST_F(ggTest, ldr_pre_reg_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;

        TestField shiftType(0, 3, 1) ;
        TestField shiftAmount(0, 0x1f, 1) ;
        TestField RmValue(0, 0xff, 1) ;

        TestField uFlag(0, 1, 1) ;
        TestField wFlag(0, 1, 1) ;

        for (int i = 0x2000000, j = 0 ; i <= 0x203ffff ; i += 4) {
            instance._mem.Write32(i, testValue[ j ]) ;
            egg.writeWord(i, testValue[ j ]) ;

            j = (j + 1) & 0b11 ;
        } // for

        auto TestMain = [&]() {
            ++t ;

            if (wFlag.value && targetRn.value == pc)
                return ;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return ;

            uint32_t offset = RmValue.value ;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value ;
                    break;
                case LSR:
                    offset >>= shiftAmount.value ;
                    break ;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value ;
                    break ;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break ;
            }

            if (uFlag.value && (baseAddr + offset < 0x2000000 || baseAddr + offset > 0x203ffff))
                return ;
            if (!uFlag.value && (baseAddr - offset < 0x2000000 || baseAddr - offset > 0x203ffff))
                return ;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, true, uFlag.value, false, wFlag.value, true,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._status._regs[ r4 ] = RmValue.value ;
            egg.regs[ r4 ] = RmValue.value ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue) ;
        std::cout << "Test performed: " << t << std::endl ;
    }

    TEST_F(ggTest, ldrb_pre_imm_offset_test) {
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
            if (uFlag.value)
                targetAddr += immOffset.value ;
            else
                targetAddr -= immOffset.value ;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, true, uFlag.value, true, wFlag.value, true,
                    targetRn.value, targetRd.value, immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._mem.Write32(targetAddr, testValue[memValueidx.value]) ;
            egg.writeWord(targetAddr, testValue[memValueidx.value]) ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

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

    TEST_F(ggTest, ldrb_pre_reg_offset_test) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm ;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;

        TestField shiftType(0, 3, 1) ;
        TestField shiftAmount(0, 0x1f, 1) ;
        TestField RmValue(0, 0xff, 1) ;

        TestField uFlag(0, 1, 1) ;
        TestField wFlag(0, 1, 1) ;

        for (int i = 0x2000000, j = 0 ; i <= 0x203ffff ; i += 4) {
            instance._mem.Write32(i, testValue[ j ]) ;
            egg.writeWord(i, testValue[ j ]) ;

            j = (j + 1) & 0b11 ;
        } // for

        auto TestMain = [&]() {
            ++t ;

            if (wFlag.value && targetRn.value == pc)
                return ;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return ;

            uint32_t offset = RmValue.value ;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value ;
                    break;
                case LSR:
                    offset >>= shiftAmount.value ;
                    break ;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value ;
                    break ;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break ;
            }

            if (uFlag.value && (baseAddr + offset < 0x2000000 || baseAddr + offset > 0x203ffff))
                return ;
            if (!uFlag.value && (baseAddr - offset < 0x2000000 || baseAddr - offset > 0x203ffff))
                return ;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, true, uFlag.value, true, wFlag.value, true,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            ) ;

            instance._status._regs[ targetRn.value ] = baseAddr ;
            egg.regs[ targetRn.value ] = baseAddr ;

            instance._status._regs[ r4 ] = RmValue.value ;
            egg.regs[ r4 ] = RmValue.value ;

            uint32_t inst_hash = hashArm(instruction) ;

            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg) ;
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) ;
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue) ;
        std::cout << "Test performed: " << t << std::endl ;
    }
}
//
// Created by buildmachine on 2021-01-07.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    const uint32_t baseAddr = 0x0201ff00;
    static constexpr std::array<uint32_t, 4> testValue{
            0xdeadbeef,
            0xa0b1c2d4,
            0x0c0011ab,
            0xffffffff
    };

    TEST_F(ggTest, arm_str_post_imm_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xe, 1);
        TestField targetRd(0, 0xf, 1);
        TestField immOffset(0, 0xfff, 1);
        TestField memValueidx(0, 3, 1);

        TestField uFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;

            if (targetRd.value == targetRn.value)
                return;

            uint32_t targetAddr = baseAddr;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, false, false, false,
                    targetRn.value, targetRd.value, immOffset.value
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueidx.value];
            egg.regs[targetRd.value] = testValue[memValueidx.value];

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(baseAddr) == egg.readWordRotate(baseAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << std::boolalpha << " memChk: " << memChk
                                        << '\n'
                                        << fmt::format("Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) << '\n'
                                        << "memread_mine:" << instance._mem.Read32(baseAddr) << " ref: "
                                        << egg.readWordRotate(baseAddr) << '\n';
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, immOffset, memValueidx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_str_post_reg_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xe, 1);
        TestField targetRd(0, 0xf, 1);

        TestField shiftType(0, 3, 1);
        TestField shiftAmount(0, 0x1f, 1);
        TestField RmValue(0, 0xff, 1);
        TestField memValueidx(0, 3, 1);

        TestField uFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;

            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return;

            uint32_t offset = RmValue.value, targetAddr = 0;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value;
                    break;
                case LSR:
                    offset >>= shiftAmount.value;
                    break;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value;
                    break;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break;
            }

            targetAddr = uFlag.value ? baseAddr + offset : baseAddr - offset;

            if (targetAddr < 0x2000000 || targetAddr > 0x203ffff)
                return;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, false, uFlag.value, false, false, false,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueidx.value];
            egg.regs[targetRd.value] = testValue[memValueidx.value];

            instance._regs[r4] = RmValue.value;
            egg.regs[r4] = RmValue.value;

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(baseAddr) == egg.readWordRotate(baseAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue, memValueidx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_strb_post_imm_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xe, 1);
        TestField targetRd(0, 0xf, 1);
        TestField immOffset(0, 0xfff, 1);
        TestField memValueidx(0, 3, 1);

        TestField uFlag(0, 1, 1);

        for (int i = 0x2000000; i <= 0x203ffff; i += 4) {
            instance._mem.Write32(i, 0u);
            egg.writeWord(i, 0);
        } // for

        auto TestMain = [&]() {
            ++t;

            uint32_t targetAddr = baseAddr;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, false, uFlag.value, true, false, false,
                    targetRn.value, targetRd.value, immOffset.value
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueidx.value];
            egg.regs[targetRd.value] = testValue[memValueidx.value];

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(baseAddr) == egg.readWordRotate(baseAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << std::boolalpha << " memChk: " << memChk
                                        << '\n'
                                        << fmt::format("Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, immOffset, memValueidx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_strb_post_reg_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xe, 1);
        TestField targetRd(0, 0xf, 1);

        TestField shiftType(0, 3, 1);
        TestField shiftAmount(0, 0x1f, 1);
        TestField RmValue(0, 0xff, 1);
        TestField memValueidx(0, 3, 1);

        TestField uFlag(0, 1, 1);

        for (int i = 0x2000000; i <= 0x203ffff; i += 4) {
            instance._mem.Write32(i, 0u);
            egg.writeWord(i, 0);
        } // for

        auto TestMain = [&]() {
            ++t;

            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return;

            uint32_t offset = RmValue.value, targetAddr = 0;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value;
                    break;
                case LSR:
                    offset >>= shiftAmount.value;
                    break;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value;
                    break;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break;
            }

            targetAddr = uFlag.value ? baseAddr + offset : baseAddr - offset;

            if (targetAddr < 0x2000000 || targetAddr > 0x203ffff)
                return;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, false, uFlag.value, true, false, false,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueidx.value];
            egg.regs[targetRd.value] = testValue[memValueidx.value];

            instance._regs[r4] = RmValue.value;
            egg.regs[r4] = RmValue.value;

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(baseAddr) == egg.readWordRotate(baseAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue, memValueidx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_str_pre_imm_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xf, 1);
        TestField targetRd(0, 0xf, 1);
        TestField immOffset(0, 0xfff, 1);
        TestField memValueIdx(0, 3, 1);

        TestField uFlag(0, 1, 1);
        TestField wFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;

            if (targetRn.value == targetRd.value)
                return;

            if (wFlag.value && targetRn.value == pc)
                return;

            uint32_t targetAddr = uFlag.value ? baseAddr + immOffset.value : baseAddr - immOffset.value;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, true, uFlag.value, false, wFlag.value, false,
                    targetRn.value, targetRd.value, immOffset.value
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueIdx.value];
            egg.regs[targetRd.value] = testValue[memValueIdx.value];

            uint32_t inst_hash = hashArm(instruction);

            if (t == 16389)
                std::cout << std::endl;

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(targetAddr) == egg.readWordRotate(targetAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << fmt::format("Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, immOffset, memValueIdx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_str_pre_reg_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xf, 1);
        TestField targetRd(0, 0xf, 1);

        TestField shiftType(0, 3, 1);
        TestField shiftAmount(0, 0x1f, 1);
        TestField RmValue(0, 0xff, 1);
        TestField memValueIdx(0, 3, 1);

        TestField uFlag(0, 1, 1);
        TestField wFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;

            if (wFlag.value && targetRn.value == pc)
                return;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return;

            uint32_t offset = RmValue.value;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value;
                    break;
                case LSR:
                    offset >>= shiftAmount.value;
                    break;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value;
                    break;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break;
            }

            uint32_t targetAddr = uFlag.value ? baseAddr + offset : baseAddr - offset;
            if (targetAddr < 0x2000000 || targetAddr > 0x203ffff)
                return;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, true, uFlag.value, false, wFlag.value, false,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueIdx.value];
            egg.regs[targetRd.value] = testValue[memValueIdx.value];

            instance._regs[r4] = RmValue.value;
            egg.regs[r4] = RmValue.value;

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(targetAddr) == egg.readWordRotate(targetAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue, memValueIdx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_strb_pre_imm_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xf, 1);
        TestField targetRd(0, 0xf, 1);
        TestField immOffset(0, 0xfff, 1);
        TestField memValueidx(0, 3, 1);

        TestField uFlag(0, 1, 1);
        TestField wFlag(0, 1, 1);

        for (int i = 0x2000000; i <= 0x203ffff; i += 4) {
            instance._mem.Write32(i, 0u);
            egg.writeWord(i, 0);
        } // for

        auto TestMain = [&]() {
            ++t;

            if (wFlag.value && targetRn.value == pc)
                return;

            uint32_t targetAddr = uFlag.value ? baseAddr + immOffset.value : baseAddr - immOffset.value;

            uint32_t instruction = MakeSingleTransferInstruction<Cond, F_Type::I, P, U, B, W, L, Rn, Rd, F_Type::Imm>(
                    AL, false, true, uFlag.value, true, wFlag.value, false,
                    targetRn.value, targetRd.value, immOffset.value
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueidx.value];
            egg.regs[targetRd.value] = testValue[memValueidx.value];

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(targetAddr) == egg.readWordRotate(targetAddr);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << fmt::format("Testcase: offset: {:x}\n", immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, immOffset, memValueidx);
        std::cout << "Test performed: " << t << std::endl;
    }

    TEST_F(ggTest, arm_strb_pre_reg_offset_test) {
        unsigned int t = 0;
        TestField targetRn(0, 0xf, 1);
        TestField targetRd(0, 0xf, 1);

        TestField shiftType(0, 3, 1);
        TestField shiftAmount(0, 0x1f, 1);
        TestField RmValue(0, 0xff, 1);
        TestField memValueIdx(0, 3, 1);

        TestField uFlag(0, 1, 1);
        TestField wFlag(0, 1, 1);

        for (int i = 0x2000000; i <= 0x203ffff; i += 4) {
            instance._mem.Write32(i, 0u);
            egg.writeWord(i, 0);
        } // for

        auto TestMain = [&]() {
            ++t;

            if (wFlag.value && targetRn.value == pc)
                return;
            if (targetRd.value == targetRn.value || r4 == targetRn.value)
                return;

            uint32_t offset = RmValue.value;
            switch (shiftType.value) {
                case LSL:
                    offset <<= shiftAmount.value;
                    break;
                case LSR:
                    offset >>= shiftAmount.value;
                    break;
                case ASR:
                    offset = static_cast<int32_t>(offset) >> shiftAmount.value;
                    break;
                case ROR:
                    offset = rotr(offset, shiftAmount.value);
                    break;
            }

            uint32_t targetAddr = uFlag.value ? baseAddr + offset : baseAddr - offset;
            if (targetAddr < 0x2000000 || targetAddr > 0x203ffff)
                return;

            uint32_t instruction = MakeSingleTransferInstruction
                    <Cond, F_Type::I, P, U, B, W, L, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                    AL, true, true, uFlag.value, true, wFlag.value, false,
                    targetRn.value, targetRd.value, shiftAmount.value, shiftType.value, r4
            );

            instance._regs[targetRn.value] = baseAddr;
            egg.regs[targetRn.value] = baseAddr;

            instance._regs[targetRd.value] = testValue[memValueIdx.value];
            egg.regs[targetRd.value] = testValue[memValueIdx.value];

            instance._regs[r4] = RmValue.value;
            egg.regs[r4] = RmValue.value;

            uint32_t inst_hash = hashArm(instruction);

            EggRun(egg, instruction);
            instance.CPU_Test(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            uint32_t memChk = instance._mem.Read32(targetAddr) == egg.readWordRotate(targetAddr);
            ASSERT_TRUE(errFlag == 0 && memChk)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << " memChk: " << std::boolalpha << memChk
                                        << '\n'
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag);
            CpuPC_Reset(egg, instance);
        };

        TEST_LOOPS(TestMain, uFlag, wFlag, targetRn, targetRd, shiftType, shiftAmount, RmValue, memValueIdx);
        std::cout << "Test performed: " << t << std::endl;
    }
}
//
// Created by buildmachine on 2021-01-11.
//

#include <gg_test.h>

// TODO: ldrsb test

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    static constexpr std::array<uint16_t, 4> testValue{
            0xbeef,
            0x7274,
            0xa1ab,
            0x0f4f
    };

    TEST_F(ggTest, ldrh_reg_post_offset) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;
        TestField targetRm(0, 0xe, 1) ;

        TestField RmValue(0, 0x3ffff, 2) ;
        std::pair<uint32_t, bool> addrPair[2] = {
                std::make_pair(0x02000000, true),
                std::make_pair(0x0203fffe, false)
        };

        TestField writeMode(0, 1, 1) ;
        TestField memValueIdx(0, 3, 1);
        TestField sFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;
            if (targetRn.value == targetRm.value || targetRn.value == targetRd.value)
                return ;

            uint32_t instruction = MakeHalfTransferInstruction<Cond, P, U, W, L, Rn, Rd, S, H, Rm>(
                    AL,
                    false, // false for post-index
                    addrPair[writeMode.value].second, // decided by writeMode
                    false, // post-index is always W == false
                    true, // true for ldr
                    targetRn.value,
                    targetRd.value,
                    sFlag.value, true, // 01 for unsigned halfword access
                    targetRm.value
            ) ;

            instance._status._regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            instance._status._regs[ targetRm.value ] = RmValue.value ;
            instance._mem.Write16(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            egg.regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            egg.regs[ targetRm.value ] = RmValue.value ;
            egg.writeHalf(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            // uint32_t memChk = instance._status._regs[targetRd.value] == egg.readHalfRotate(RmValue.value);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: baseAddr: 0x{:x}, offsetRm: {:x}\n", addrPair[ writeMode.value ].first, RmValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) << '\n' ;
        };

        TEST_LOOPS(TestMain, targetRn, targetRd,targetRm, RmValue, writeMode, memValueIdx, sFlag);
    }

    TEST_F(ggTest, ldrh_imm_post_offset) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;
        TestField immOffset(0, 0x3ffff, 2) ;

        std::pair<uint32_t, bool> addrPair[2] = {
                std::make_pair(0x02000000, true),
                std::make_pair(0x0203fffe, false)
        };

        TestField writeMode(0, 1, 1) ;
        TestField memValueIdx(0, 3, 1);
        TestField sFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;
            if (targetRn.value == targetRd.value)
                return ;

            uint32_t instruction = MakeHalfTransferInstruction<Cond, P, U, W, L, Rn, Rd, S, H, Offset>(
                    AL,
                    false, // false for post-index
                    addrPair[writeMode.value].second, // decided by writeMode
                    false, // post-index is always W == false
                    true, // true for ldr
                    targetRn.value,
                    targetRd.value,
                    sFlag.value, true, // 01 for unsigned halfword access
                    immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            instance._mem.Write16(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            egg.regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            egg.writeHalf(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            // uint32_t memChk = instance._status._regs[targetRd.value] == egg.readHalfRotate(RmValue.value);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: baseAddr: 0x{:x}, immOffset: {:x}\n", addrPair[ writeMode.value ].first, immOffset.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) << '\n' ;
        };

        TEST_LOOPS(TestMain, targetRn, targetRd, immOffset, writeMode, memValueIdx, sFlag);
    }

    TEST_F(ggTest, ldrh_reg_pre_offset) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;
        TestField targetRm(0, 0xe, 1) ;

        TestField RmValue(0, 0x3ffff, 2) ;
        std::pair<uint32_t, bool> addrPair[2] = {
                std::make_pair(0x02000000, true),
                std::make_pair(0x0203fffe, false)
        };

        TestField writeMode(0, 1, 1) ;
        TestField memValueIdx(0, 3, 1);
        TestField wFlag(0, 1, 1);
        TestField sFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;
            if (targetRn.value == targetRm.value || targetRn.value == targetRd.value)
                return ;

            uint32_t instruction = MakeHalfTransferInstruction<Cond, P, U, W, L, Rn, Rd, S, H, Rm>(
                    AL,
                    true, // true for pre-index
                    addrPair[writeMode.value].second, // decided by writeMode
                    wFlag.value, // post-index is always W == false
                    true, // true for ldr
                    targetRn.value,
                    targetRd.value,
                    sFlag.value, true, // 01 for unsigned halfword access, 11 for singed halfword access
                    targetRm.value
            ) ;

            instance._status._regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            instance._status._regs[ targetRm.value ] = RmValue.value ;

            egg.regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            egg.regs[ targetRm.value ] = RmValue.value ;

            uint32_t targetAddr = addrPair[ writeMode.value ].first ;
            targetAddr = addrPair[ writeMode.value ].second ? targetAddr + RmValue.value : targetAddr - RmValue.value ;
            if (targetRn.value == gg_cpu::pc)
                targetAddr = addrPair[ writeMode.value ].second ? targetAddr + 4 : targetAddr - 4 ;

            instance._mem.Write16(targetAddr, testValue[ memValueIdx.value ]) ;
            egg.writeHalf(targetAddr, testValue[ memValueIdx.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            // uint32_t memChk = instance._status._regs[targetRd.value] == egg.readHalfRotate(RmValue.value);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: baseAddr: 0x{:x}, offsetRm: {:x}\n", addrPair[ writeMode.value ].first, RmValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) << '\n' ;
        };

        TEST_LOOPS(TestMain, targetRn, targetRd,targetRm, RmValue, writeMode, memValueIdx, wFlag, sFlag);
    }

    TEST_F(ggTest, ldrh_imm_pre_offset) {
        Arm egg;
        gg_core::GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0 ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRd(0, 0xf, 1) ;

        TestField immOffset(0, 0xff, 2) ;
        std::pair<uint32_t, bool> addrPair[2] = {
                std::make_pair(0x02000000, true),
                std::make_pair(0x0203fffe, false)
        };

        TestField writeMode(0, 1, 1) ;
        TestField memValueIdx(0, 3, 1);
        TestField wFlag(0, 1, 1);
        TestField sFlag(0, 1, 1);

        auto TestMain = [&]() {
            ++t;
            if (targetRn.value == targetRd.value)
                return ;

            uint32_t instruction = MakeHalfTransferInstruction<Cond, P, U, W, L, Rn, Rd, S, H, Offset>(
                    AL,
                    true, // true for pre-index
                    addrPair[writeMode.value].second, // decided by writeMode
                    wFlag.value, // post-index is always W == false
                    true, // true for ldr
                    targetRn.value,
                    targetRd.value,
                    sFlag.value, true, // 01 for unsigned halfword access, 11 for singed halfword access
                    immOffset.value
            ) ;

            instance._status._regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            egg.regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;

            uint32_t targetAddr = addrPair[ writeMode.value ].first ;
            targetAddr = addrPair[ writeMode.value ].second ? targetAddr + immOffset.value : targetAddr - immOffset.value ;
            if (targetRn.value == gg_cpu::pc)
                targetAddr = addrPair[ writeMode.value ].second ? targetAddr + 4 : targetAddr - 4 ;

            instance._mem.Write16(targetAddr, testValue[ memValueIdx.value ]) ;
            egg.writeHalf(targetAddr, testValue[ memValueIdx.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUStep(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            // uint32_t memChk = instance._status._regs[targetRd.value] == egg.readHalfRotate(RmValue.value);
            ASSERT_TRUE(errFlag == 0)
                << "#" << t << '\n'
                << std::hex << "Errflag: " << errFlag << '\n'
                << fmt::format("Testcase: baseAddr: 0x{:x}, offsetImm: {:x}\n", addrPair[ writeMode.value ].first, immOffset.value)
                << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                << Diagnose(instance, egg, errFlag) << '\n' ;
        };

        TEST_LOOPS(TestMain, targetRn, targetRd, immOffset, writeMode, memValueIdx, wFlag, sFlag);
    }
}
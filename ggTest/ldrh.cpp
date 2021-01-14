//
// Created by buildmachine on 2021-01-11.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    static constexpr std::array<uint32_t, 4> testValue{
            0xdeadbeef,
            0xa0b1c2d4,
            0x0c0011ab,
            0xffffffff
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
                    false, true, // 01 for unsigned halfword access
                    targetRm.value
            ) ;

            instance._status._regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            instance._status._regs[ targetRm.value ] = RmValue.value ;
            instance._mem.Write32(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            egg.regs[ targetRn.value ] = addrPair[ writeMode.value ].first ;
            egg.regs[ targetRm.value ] = RmValue.value ;
            egg.writeWord(addrPair[ writeMode.value ].first, testValue[ memValueIdx.value ]) ;

            uint32_t inst_hash = hashArm(instruction) ;
            std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            instance.CPUTick_Debug(instruction);

            uint32_t errFlag = CheckStatus(instance, egg);
            // uint32_t memChk = instance._status._regs[targetRd.value] == egg.readHalfRotate(RmValue.value);
            ASSERT_TRUE(errFlag == 0)
                                        << "#" << t << '\n'
                                        << std::hex << "Errflag: " << errFlag << '\n'
                                        << fmt::format("Testcase: baseAddr: 0x{:x}, offsetRm: {:x}\n", addrPair[ writeMode.value ].first, RmValue.value)
                                        << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                        << Diagnose(instance, egg, errFlag) << '\n' ;
        };

        TEST_LOOPS(TestMain, targetRn, targetRd,targetRm, RmValue, writeMode, memValueIdx);
    }
}
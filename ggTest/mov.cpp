//
// Created by jason4_lee on 2020-10-12.
//
#include <gg_test.h>
#include <loop_tool.h>
#include <thread>

namespace {
    using namespace gg_core::gg_cpu ;

    constexpr static std::array<const char*, 16> opName {
            "and", "eor", "sub", "rsb",
            "add", "adc", "sbc", "rsc",
            "tst", "teq", "cmp", "cmn",
            "orr", "mov", "bic", "mvn"
    } ;

    TEST_F(ggTest, alu_rd_rn_op2ShiftRs_test) {
        auto worker = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField FieldRs(0, 0x1ff, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rs, ShiftType, Rm>(
                        AL, operation, true, RnNumber.value, r0, r4, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value, r4) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value, FieldRs.value);
                FillRegs(instance._status._regs, egg.regs, idx, val) ;
                // dbg
                // fmt::print("{}\n", gg_asm.DASM(instruction)) ;

//                if (t == 16511)
//                    std::cout << "gg" << std::endl ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                    << "#" << t << " of test" << '\n'
                    << std::hex << "Errflag: " << errFlag << '\n'
                    << fmt::format( "Rn: {:x}, Rm: {:x}, Rs: {:x}\n", FieldRn.value, FieldRm.value, FieldRs.value )
                    << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                    << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType) ;
            fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
        };

        std::vector<std::thread> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
            workers.emplace_back(worker, static_cast<E_DataProcess>(i)) ;
        } // for

        for (auto& t : workers)
            t.join();
//        worker(MVN) ;
    }
}
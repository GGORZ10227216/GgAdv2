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

            uint64_t t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField FieldRs(0, 0x1ff, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;
            TestField cpsr(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rs, ShiftType, Rm>(
                        AL, operation, true, RnNumber.value, r0, r4, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value, r4) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value, FieldRs.value);
                FillRegs(instance._status._regs, idx, val) ;
                FillRegs(egg.regs, idx, val) ;

                egg.cpsr = (cpsr.value << 28) | 0xd3 ;
                instance._status.WriteCPSR(cpsr.value << 28 | 0xd3) ;

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

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType, cpsr) ;
            fmt::print("[{}] Total numbers of performed test: {}\n", opName[operation], t) ;
        };

        std::vector<std::thread> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
            workers.emplace_back(worker, static_cast<E_DataProcess>(i)) ;
        } // for

        for (auto& t : workers)
            t.join();
//        worker(ADC) ;
    }

    TEST_F(ggTest, egg_speed_test) {
        auto worker = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;

            uint64_t t = 0 ;
            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField FieldRs(0, 0x1ff, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;
            TestField cpsr(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rs, ShiftType, Rm>(
                        AL, operation, true, RnNumber.value, r0, r4, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value, r4) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value, FieldRs.value);
                FillRegs(egg.regs, idx, val) ;

                egg.cpsr = (cpsr.value << 28) | 0xd3 ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType, cpsr) ;
            fmt::print("[{}] Total numbers of performed test: {}\n", opName[operation], t) ;
        };

        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
            auto start = std::chrono::system_clock::now();
            worker(static_cast<E_DataProcess>(i)) ;
            auto end = std::chrono::system_clock::now();

            std::chrono::duration<double> diff = end - start ;
            std::cout << '[' << opName[i] << "] " << diff.count() << std::endl ;
        } // for
    }

    TEST_F(ggTest, ggadv2_speed_test) {
        auto worker = [&](E_DataProcess operation) {
            using namespace gg_core ;

            gg_core::GbaInstance instance(std::nullopt);

            uint64_t t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField FieldRs(0, 0x1ff, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;
            TestField cpsr(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rs, ShiftType, Rm>(
                        AL, operation, true, RnNumber.value, r0, r4, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value, r4) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value, FieldRs.value);
                FillRegs(instance._status._regs, idx, val) ;

                instance._status.WriteCPSR(cpsr.value << 28 | 0xd3) ;
                instance.CPUTick_Debug(instruction);
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType, cpsr) ;
            fmt::print("[{}] Total numbers of performed test: {}\n", opName[operation], t) ;
        };



//        for (int i = 0 ; i < 16 ; ++i) {
//            std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
//            auto start = std::chrono::system_clock::now();
//            worker(static_cast<E_DataProcess>(i)) ;
//            auto end = std::chrono::system_clock::now();
//
//            std::chrono::duration<double> diff = end - start ;
//            std::cout << '[' << opName[i] << "] " << diff.count() << std::endl ;
//        } // for
        auto start = std::chrono::system_clock::now();
        worker(SBC) ;
        auto end = std::chrono::system_clock::now();
    }

//    TEST_F(ggTest, test) {
//        using namespace gg_core ;
//
//        Arm egg;
//        gg_core::GbaInstance instance(std::nullopt);
//        ArmAssembler gg_asm ;
//
//        uint32_t instruction = gg_asm.ASM("sbcs r0, r1, r0, asr r4") ;
//        auto idx = std::make_tuple(r1, r0, r4) ;
//        auto val = std::make_tuple(0, 0x8000'0000, 0x1f);
//        FillRegs(instance._status._regs, egg.regs, idx, val) ;
//
//        instance._status.SetC() ;
//        egg.cpsr.c = 1 ;
//
//        uint32_t inst_hash = hashArm(instruction) ;
//        std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
//        instance.CPUTick_Debug(instruction);
//
//        std::cout << "Reg values:" << std::endl ;
//        for (size_t i = 0 ; i < 16 ; ++i) {
//            fmt::print("\tr{}: mine=0x{:x}, ref=0x{:x}\n", i, instance._status._regs[i], egg.regs[i]) ;
//        } // for
//
//        fmt::print("\tcpsr[NZCV]: mine={:x}, ref={:x}\n", instance._status.ReadCPSR() >> 28, egg.cpsr >> 28 ) ;
//    }
}
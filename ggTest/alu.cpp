//
// Created by jason4_lee on 2020-10-12.
//
#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu ;

    const static std::array<std::string, 16> opName {
            "and", "eor", "sub", "rsb",
            "add", "adc", "sbc", "rsc",
            "tst", "teq", "cmp", "cmn",
            "orr", "mov", "bic", "mvn"
    } ;

    TEST_F(ggTest, alu_rd_rn_op2ShiftRs_cpsr_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

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
                    << "#" << t << " of test(" << operation << ")" << '\n'
                    << std::hex << "Errflag: " << errFlag << '\n'
                    << fmt::format( "Rn: {:x}, Rm: {:x}, Rs: {:x}\n", FieldRn.value, FieldRm.value, FieldRs.value )
                    << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                    << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType, cpsr) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::string op = opName[i] ;
            if (i < 0b1000 || i > 0b1011)
                op += 's' ;

            std::cout << '[' << op << "]" << "start!" << std::endl ;
            auto result = std::make_pair(
                    op,
                    std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
            ) ;

            workers.push_back(std::move(result)) ;
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }

    TEST_F(ggTest, alu_rd_rn_op2ShiftRs_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField FieldRs(0, 0x1ff, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rs, ShiftType, Rm>(
                        AL, operation, false, RnNumber.value, r0, r4, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value, r4) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value, FieldRs.value);
                FillRegs(instance._status._regs, idx, val) ;
                FillRegs(egg.regs, idx, val) ;

                uint32_t inst_hash = hashArm(instruction) ;

                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << " of test(" << operation << ")" << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format( "Rn: {:x}, Rm: {:x}, Rs: {:x}\n", FieldRn.value, FieldRm.value, FieldRs.value )
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, FieldRs, shiftType) ;
            // fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            if (i >= 0b1000 && i <= 0b1011) {
                std::cout << "No need to check Test type instruction[" << opName[i] << "]" << std::endl ;
            } // if
            else {
                std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
                auto result = std::make_pair(
                   opName[i],
                   std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
                ) ;

                workers.push_back(std::move(result)) ;
            } // else
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }

    TEST_F(ggTest, alu_rd_rn_op2ShiftImm_cpsr_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField shiftAmount(0, 0x1f, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;
            TestField cpsr(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                        AL, operation, true, RnNumber.value, r0, shiftAmount.value, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value);
                FillRegs(instance._status._regs, idx, val) ;
                FillRegs(egg.regs, idx, val) ;

                egg.cpsr = (cpsr.value << 28) | 0xd3 ;
                instance._status.WriteCPSR(cpsr.value << 28 | 0xd3) ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << " of test(" << operation << ")" << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format( "Rn: {:x}, Rm: {:x}, shiftAmount: {:x}\n",
                                                            FieldRn.value, FieldRm.value, shiftAmount.value )
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, shiftAmount, shiftType, cpsr) ;
            // fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::string op = opName[i] ;
            if (i < 0b1000 || i > 0b1011)
                op += 's' ;

            std::cout << '[' << op << "]" << "start!" << std::endl ;
            auto result = std::make_pair(
                    op,
                    std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
            ) ;

            workers.push_back(std::move(result)) ;
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }

    TEST_F(ggTest, alu_rd_rn_op2ShiftImm_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField FieldRm(0, 0xffffffff, 0x11111111) ;
            TestField shiftAmount(0, 0x1f, 1) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RmNumber(0, 0xf, 1) ;
            TestField shiftType(0, 3, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, ShiftAmount, ShiftType, Rm>(
                        AL, operation, false, RnNumber.value, r0, shiftAmount.value, shiftType.value, RmNumber.value
                ) ;

                auto idx = std::make_tuple(RnNumber.value, RmNumber.value) ;
                auto val = std::make_tuple(FieldRn.value, FieldRm.value);
                FillRegs(instance._status._regs, idx, val) ;
                FillRegs(egg.regs, idx, val) ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << " of test(" << operation << ")" << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format( "Rn: {:x}, Rm: {:x}, shiftAmount: {:x}\n",
                                                            FieldRn.value, FieldRm.value, shiftAmount.value )
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RmNumber, RnNumber, FieldRn, FieldRm, shiftAmount, shiftType) ;
            // fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            if (i >= 0b1000 && i <= 0b1011) {
                std::cout << "No need to check Test type instruction[" << opName[i] << "]" << std::endl ;
            } // if
            else {
                std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
                auto result = std::make_pair(
                        opName[i],
                        std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
                ) ;

                workers.push_back(std::move(result)) ;
            } // else
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }

    TEST_F(ggTest, alu_rd_rn_op2Imm_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RdNumber(0, 0xe, 1) ; // 0xe for prevent writing to pc
            TestField imm(0, 0xff, 1) ;
            TestField rotate(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rotate, Imm>(
                        AL, operation, false, RnNumber.value, RdNumber.value, rotate.value, imm.value
                ) ;

                instance._status._regs[ RnNumber.value ] = FieldRn.value ;
                egg.regs[ RnNumber.value ] = FieldRn.value ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << " of test(" << operation << ")" << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format( "Rn: {:x}, imm: {:x}, rotate: {:x}\n",
                                                            FieldRn.value, imm.value, rotate.value )
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RdNumber, RnNumber, FieldRn, imm, rotate) ;
            // fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            if (i >= 0b1000 && i <= 0b1011) {
                std::cout << "No need to check Test type instruction[" << opName[i] << "]" << std::endl ;
            } // if
            else {
                std::cout << '[' << opName[i] << ']' << "start!" << std::endl ;
                auto result = std::make_pair(
                        opName[i],
                        std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
                ) ;

                workers.push_back(std::move(result)) ;
            } // else
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }

    TEST_F(ggTest, alu_rd_rn_op2Imm_cpsr_test) {
        auto task = [&](E_DataProcess operation) {
            using namespace gg_core ;

            Arm egg;
            gg_core::GbaInstance instance(std::nullopt);
            ArmAssembler gg_asm ;

            unsigned int t = 0 ;

            TestField FieldRn(0, 0xffffffff, 0x11111111) ;
            TestField RnNumber(0, 0xf, 1) ;
            TestField RdNumber(0, 0xe, 1) ; // 0xe for prevent writing to pc
            TestField imm(0, 0xff, 1) ;
            TestField rotate(0, 0xf, 1) ;
            TestField cpsr(0, 0xf, 1) ;

            auto TestMain = [&]() {
                ++t ;
                uint32_t instruction = MakeALUInstruction<Cond, OpCode, S, Rn, Rd, Rotate, Imm>(
                        AL, operation, true, RnNumber.value, RdNumber.value, rotate.value, imm.value
                ) ;

                instance._status._regs[ RnNumber.value ] = FieldRn.value ;
                egg.regs[ RnNumber.value ] = FieldRn.value ;

                egg.cpsr = (cpsr.value << 28) | 0xd3 ;
                instance._status.WriteCPSR(cpsr.value << 28 | 0xd3) ;

                uint32_t inst_hash = hashArm(instruction) ;
                std::invoke(egg.instr_arm[inst_hash], &egg, instruction);
                instance.CPUTick_Debug(instruction);

                uint32_t errFlag = CheckStatus(instance, egg) ;
                ASSERT_TRUE(errFlag == 0)
                                            << "#" << t << " of test(" << operation << ")" << '\n'
                                            << std::hex << "Errflag: " << errFlag << '\n'
                                            << fmt::format( "Rn: {:x}, imm: {:x}, rotate: {:x}\n",
                                                            FieldRn.value, imm.value, rotate.value )
                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                            << Diagnose(instance, egg, errFlag) ;
            };

            TEST_LOOPS(TestMain, RdNumber, RnNumber, FieldRn, imm, rotate, cpsr) ;
            // fmt::print("[{}] Total performed tests: {}\n", opName[operation], t) ;
            return t ;
        };

        std::vector<WorkerResult> workers ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::string op = opName[i] ;
            if (i < 0b1000 || i > 0b1011)
                op += 's' ;

            std::cout << '[' << op << "]" << "start!" << std::endl ;
            auto result = std::make_pair(
                    op,
                    std::async(std::launch::async, task, static_cast<E_DataProcess>(i))
            ) ;

            workers.push_back(std::move(result)) ;
        } // for

        for (auto& t : workers)
            fmt::print("[{}] Total performed tests: {}\n", t.first, t.second.get()) ;
    }
}
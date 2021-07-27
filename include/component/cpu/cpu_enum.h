//
// Created by orzgg on 2020-09-03.
//

#ifndef GGADV_CPU_ENUM_H
#define GGADV_CPU_ENUM_H

namespace gg_core::gg_cpu {
//    using Regs = std::array<unsigned, 16>;

    enum E_OperationMode {
        USR = 0b10000, FIQ = 0b10001,
        IRQ = 0b10010, SVC = 0b10011,
        ABT = 0b10111, SYS = 0b11111,
        UND = 0b11011
    };

    enum E_ExceptionVector {
        RESET = 0x0,
        UNDEFINED_INSTRUCTION = 0x4,
        SW_IRQ = 0x8,
        ABORT_PREFETCH = 0xC,
        ABORT_DATA = 0x10,
        HW_IRQ = 0x18
    };

    enum E_CpuMode {
        ARM, THUMB
    };

    enum E_RegName {
        r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc
    };

    enum E_ShiftType {
        LSL, LSR, ASR, ROR
    };

    enum E_DataProcess {
        AND, EOR, SUB, RSB, ADD, ADC, SBC, RSC, TST, TEQ, CMP, CMN, ORR, MOV, BIC, MVN
    };

//    enum class E_ThumbType4Op {
//        AND = E_DataProcess::AND, EOR = E_DataProcess::EOR,
//        LSL = E_DataProcess::MOV, LSR = E_DataProcess::MOV,
//        ASR = E_DataProcess::MOV, ADC = E_DataProcess::ADC,
//        SBC = E_DataProcess::SBC, ROR = E_DataProcess::MOV,
//        TST = E_DataProcess::TST, NEG = E_DataProcess::RSB,
//        CMP = E_DataProcess::CMP, CMN = E_DataProcess::CMN,
//        ORR = E_DataProcess::ORR, MUL,
//        BIC = E_DataProcess::BIC, MVN = E_DataProcess::MVN
//    };

    enum E_CondName {
        EQ, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL
    };

    enum E_PSRBit {
        T = 5, F = 6, I = 7, V = 28, C = 29, Z = 30, N = 31
    };

    enum E_PipelineStage {
        Execute, Decode, Fetched
    };

    enum class OP_TYPE { LOGICAL, ARITHMETIC, TEST } ;

    enum class SHIFT_BY {
        RS, IMM, NONE
    };
    enum class SHIFT_TYPE {
        LSL, LSR, ASR, ROR, NONE
    };

    enum class OFFSET_TYPE { RM, IMM };

}

#endif //GGADV_CPU_ENUM_H

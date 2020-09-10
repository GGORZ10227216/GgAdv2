//
// Created by orzgg on 2020-09-03.
//

#ifndef GGADV_CPU_ENUM_H
#define GGADV_CPU_ENUM_H

namespace gg_core::gg_cpu {
    using Regs = std::array<unsigned, 16>;

    enum E_OperationMode {
        USR = 0b10000, FIQ = 0b10001,
        IRQ = 0b10010, SVC = 0b10011,
        ABT = 0b10111, SYS = 0b11111,
        UND = 0b11011
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

    enum E_CondName {
        EQ, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL
    };

    enum E_PSRBit {
        T = 5, F = 6, I = 7, V = 28, C = 29, Z = 30, N = 31
    };

    enum E_PipelineStage {
        Execute, Decode, Fetched
    };

}

#endif //GGADV_CPU_ENUM_H

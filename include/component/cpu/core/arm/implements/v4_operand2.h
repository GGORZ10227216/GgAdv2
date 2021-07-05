//
// Created by buildmachine on 2020-11-27.
//

#include <cstdint>
#include <cpu_enum.h>

#ifndef GGTEST_V4_OPERAND2_H
#define GGTEST_V4_OPERAND2_H

namespace gg_core::gg_cpu {
    template <SHIFT_TYPE ST>
    inline bool ParseOp2_Shift_RS(CPU &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RmNumber = curInst & 0b1111 ;
        const uint8_t RsNumber = (curInst & 0xf00) >> 8 ;

        uint32_t Rm = instance._regs[ RmNumber ] ;
        uint32_t Rs = instance._regs[ RsNumber ] & 0xff ;
        bool carry = false, validShift = false ;

        if (RmNumber == pc)
            Rm = (Rm + 4) ;

        if constexpr (ST == SHIFT_TYPE::LSL) {
            // todo: Does the behavior of shift_by_Rs_eq_zero and shift_by_imm_eq_zero same?
            if (Rs == 0) {
                op2 = Rm ;
                carry = instance.C() ;
            } // if
            else if (Rs < 32) {
                op2 = Rm << Rs ;
                carry = TestBit(Rm, 33 - (Rs + 1)) ;
                validShift = true ;
            } // else if
            else {
                op2 = 0 ;
                carry = Rs == 32 && TestBit(Rm, 0);
                validShift = true ;
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::LSR) {
            if (Rs == 0) {
                op2 = Rm ;
                carry = instance.C() ;
            } // if
            else if (Rs < 32) {
                op2 = Rm >> Rs ;
                carry = TestBit(Rm, Rs - 1) ;
                validShift = true ;
            } // else if
            else {
                op2 = 0 ;
                carry = Rs == 32 && TestBit(Rm, Rs - 1);
                validShift = true ;
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::ASR) {
            if (Rs >= 32) {
                validShift = true ;
                carry = TestBit(Rm, 31) ;
                op2 = carry ? 0xffffffff : 0x0 ;
            } // if
            else {
                op2 = static_cast<int32_t>(Rm) >> Rs ;
                if (Rs != 0) {
                    carry = TestBit(Rm, Rs - 1) ;
                    validShift = true ;
                } // if
                else
                    carry = instance.C() ;
            } // else if
        } // if

        if constexpr (ST == SHIFT_TYPE::ROR) {
            op2 = rotr(Rm, Rs) ;
            if (Rs == 0)
                carry = instance.C() ;
            else {
                validShift = true ;
                carry = TestBit(op2, 31) ;
            } // else
        } // if

        if (validShift)
            instance.cycle += 1 ; // Shift by reg will add 1 I_Cycle cycle

        return carry ;
    } // ParseOp2_Shift_RS()

    template <SHIFT_TYPE ST>
    inline bool ParseOp2_Shift_Imm(CPU &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        uint32_t Rm = instance._regs[ curInst & 0b1111 ] ;
        const uint8_t shiftAmount = (curInst & 0xf80) >> 7 ;

        bool carry = false ;
        if constexpr (ST == SHIFT_TYPE::LSL) {
            op2 = Rm << shiftAmount ;
            if (shiftAmount != 0)
                carry = TestBit(Rm, 33 - (shiftAmount + 1)) ;
            else
                carry = instance.C() ;
        } // if

        if constexpr (ST == SHIFT_TYPE::LSR) {
            if (shiftAmount == 0) {
                op2 = 0 ;
                carry = TestBit(Rm, 31) ;
            } // if
            else {
                op2 = Rm >> shiftAmount ;
                carry = TestBit(Rm, shiftAmount - 1) ;
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::ASR) {
            if (shiftAmount == 0) {
                carry = TestBit(Rm, 31) ;
                op2 = carry ? 0xffffffff : 0x0 ;
            } // if
            else {
                op2 = static_cast<int32_t>(Rm) >> shiftAmount ;
                carry = TestBit(Rm, shiftAmount - 1) ;
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::ROR) {
            if (shiftAmount == 0) {
                // RRX
                carry = TestBit(Rm, 0) ;
                op2 = (instance.C() << 31) | (Rm >> 1) ;
            } // if
            else {
                op2 = rotr(Rm, shiftAmount);
                carry = TestBit(op2, 31) ;
            } // else
        } // if

        return carry ;
    } // ParseOp2_Shift_Imm()

    inline bool ParseOp2_Imm(CPU &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint32_t imm = curInst & 0xff ;
        const uint8_t rot = (curInst & 0xf00) >> 7 ;
        op2 = rotr(imm, rot) ;
        if (rot == 0)
            return instance.C() ;
        else
            return TestBit(op2, 31) ;
    } // ParseOp2_Imm()
}

#endif //GGTEST_V4_OPERAND2_H

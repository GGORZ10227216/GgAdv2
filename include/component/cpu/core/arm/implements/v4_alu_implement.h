#include <type_traits>
#include <cstdint>

#include <v4_operand2.h>
#include <bit_manipulate.h>

#ifndef GGADV2_ALU_API_H
#define GGADV2_ALU_API_H

namespace gg_core::gg_cpu {
    // using alu_handler = void(*)(uint32_t&, uint32_t, uint32_t) ;
    template <E_DataProcess opcode>
    inline void CPSR_Arithmetic(CPU &instance, uint32_t Rn, uint32_t op2, uint64_t result) {
        bool needSetCarry = false, needSetOverflow = false ;
        if constexpr (opcode == ADD || opcode == CMN){
            needSetOverflow = TestBit(Rn, 31) == TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(Rn) + op2 > 0xffffffff ;
        } // if
        else if constexpr (opcode == ADC) {
            needSetOverflow = TestBit(Rn, 31) == TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(Rn) + op2 + instance.C() > 0xffffffff ;
        } // if
        else if constexpr (opcode == SUB || opcode == CMP) {
            needSetOverflow = TestBit(Rn, 31) != TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(Rn) >= op2 ;
        } // else if
        else if constexpr (opcode == SBC) {
            needSetOverflow = TestBit(Rn, 31) != TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(Rn) >= static_cast<uint64_t>(op2) - instance.C() + 1 ;
        } // else if
        else if constexpr (opcode == RSB) {
            needSetOverflow = TestBit(op2, 31) != TestBit(Rn, 31) && TestBit(op2, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(op2) >= Rn ;
        } // else if
        else if constexpr (opcode == RSC) {
            needSetOverflow = TestBit(op2, 31) != TestBit(Rn, 31) && TestBit(op2, 31) != TestBit(result, 31) ;
            needSetCarry = static_cast<uint64_t>(op2) >= static_cast<uint64_t>(Rn) - instance.C() + 1 ;
        } // else if

        needSetOverflow ? instance.SetV() : instance.ClearV() ;
        needSetCarry ? instance.SetC() : instance.ClearC() ;
    }

    template<bool I, bool S, bool TEST, SHIFT_BY SHIFT_SRC, SHIFT_TYPE ST, OP_TYPE OT, E_DataProcess opcode>
    static void Alu_impl(CPU &instance) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RnNumber = (curInst & 0xf0000) >> 16 ;

        uint32_t RnVal = instance._regs[RnNumber] ;
        uint32_t op2 = 0 ;
        bool shiftCarry = false ;

        if constexpr (I) {
            shiftCarry = ParseOp2_Imm(instance, op2) ;
        } // if
        else {
            if constexpr (SHIFT_SRC == SHIFT_BY::RS) {
                shiftCarry = ParseOp2_Shift_RS<ST>(instance, op2) ;
                if (RnNumber == pc)
                    RnVal += 4 ;
            } // if
            else
                shiftCarry = ParseOp2_Shift_Imm<ST>(instance, op2) ;
        } // else

        uint64_t result = 0;

        if constexpr (opcode == AND || opcode == TST)
            result = static_cast<uint64_t>(RnVal) & op2 ;
        else if constexpr (opcode == EOR || opcode == TEQ)
            result = static_cast<uint64_t>(RnVal) ^ op2 ;
        else if constexpr (opcode == SUB || opcode == CMP)
            result = static_cast<uint64_t>(RnVal) - op2 ;
        else if constexpr (opcode == RSB)
            result = static_cast<uint64_t>(op2) - RnVal ;
        else if constexpr (opcode == ADD || opcode == CMN)
            result = static_cast<uint64_t>(RnVal) + op2 ;
        else if constexpr (opcode == ADC)
            result = static_cast<uint64_t>(RnVal) + op2 + instance.C() ;
        else if constexpr (opcode == SBC)
            result = static_cast<uint64_t>(RnVal) - op2 + instance.C() - 1 ;
        else if constexpr (opcode == RSC)
            result = static_cast<uint64_t>(op2) - RnVal + instance.C() - 1 ;
        else if constexpr (opcode == ORR)
            result = static_cast<uint64_t>(RnVal) | op2 ;
        else if constexpr (opcode == MOV)
            result = static_cast<uint64_t>(op2) ;
        else if constexpr (opcode == BIC)
            result = static_cast<uint64_t>(RnVal) & (~op2) ;
        else if constexpr (opcode == MVN)
            result = ~op2 ;

        if constexpr (S) {
            if constexpr (OT == OP_TYPE::LOGICAL) {
                TestBit(result, 31) ? instance.SetN() : instance.ClearN() ;
                shiftCarry ? instance.SetC() : instance.ClearC() ;
                result == 0 ? instance.SetZ() : instance.ClearZ();
            } // if
            else {
                CPSR_Arithmetic<opcode> (instance, RnVal, op2, result);
                (result & 0xffffffff) == 0 ? instance.SetZ() : instance.ClearZ() ;
                TestBit(result, 31) ? instance.SetN() : instance.ClearN() ;
            } // else
        } // if

        if constexpr (!TEST) {
            const uint8_t RdNumber = (curInst & 0xf000) >> 12 ;
            instance._regs[RdNumber] = result ;
            if (RdNumber == pc) {
                instance.RefillPipeline();
                if constexpr (S) {
                    instance.WriteCPSR( instance.ReadSPSR() ) ;
                } // if
            } // if
        } // if
    }
}

#endif
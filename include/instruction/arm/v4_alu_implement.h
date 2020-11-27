#include <bit_manipulate.h>
#include <cstdint>

#include <v4_operand2.h>

#ifndef GGADV_V4_ALU_IMPLEMENT
#define GGADV_V4_ALU_IMPLEMENT

namespace gg_core::gg_cpu {
    enum class OP_TYPE { LOGICAL, ARITHMETIC, TEST } ;

    template <E_DataProcess opcode>
    inline void CPSR_Arithmetic(GbaInstance &instance, uint32_t Rn, uint32_t op2) {
        bool needSet = false ;
        if constexpr (opcode == ADD || opcode == CMN)
            needSet = static_cast<uint64_t>(Rn) + op2 > 0xffffffff ;
        else if constexpr (opcode == ADC)
            needSet = static_cast<uint64_t>(Rn) + op2 + instance._status.C() > 0xffffffff ;
        else if constexpr (opcode == SUB || opcode == CMP)
            needSet = static_cast<uint64_t>(Rn) >= op2 ;
        else if constexpr (opcode == SBC)
            needSet = static_cast<uint64_t>(Rn) >= static_cast<uint64_t>(op2) - instance._status.C() + 1 ;
        else if constexpr (opcode == RSB)
            needSet = static_cast<uint64_t>(op2) >= Rn ;
        else if constexpr (opcode == RSC)
            needSet = static_cast<uint64_t>(op2) >= static_cast<uint64_t>(Rn) - instance._status.C() + 1 ;
        needSet ? instance._status.SetC() : instance._status.ClearC() ;
    }

    // template<bool I, bool S, bool TEST, SHIFT_BY SHIFT_SRC, SHIFT_TYPE ST, OP_TYPE OT, typename F>
    template <uint32_t HashCode32>
    void DataProcessing(GbaInstance &instance)
    {
        enum {I = 25, S = 20, SHIFT_BY_RS = 4, SHIFT_TYPE = 5, SHIFT_TYPE_SIZE = 2} ;

        constexpr enum E_DataProcess opcode = static_cast<const E_DataProcess>(BitFieldValue<21, 4>(HashCode32));
        constexpr bool TEST = opcode == TST || opcode == TEQ || opcode == CMP || opcode == CMN ;
        constexpr enum OP_TYPE OT = (opcode >= SUB && opcode <= RSC) || (opcode == CMP || opcode == CMN) ?
                OP_TYPE::ARITHMETIC : OP_TYPE::LOGICAL ;

        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RnNumber = (curInst & 0xf0000) >> 16 ;

        uint32_t RnVal = instance._status._regs[RnNumber] ;
        uint32_t op2 = 0 ;
        bool shiftCarry = false ;

        if constexpr (TestBit(HashCode32, I)) {
            ParseOp2_Imm(instance, op2) ;
        } // if
        else {
            // SHIFT_SRC == SHIFT_BY::RS
            constexpr enum SHIFT_TYPE ST = static_cast<enum SHIFT_TYPE> (
                BitFieldValue<SHIFT_TYPE, SHIFT_TYPE_SIZE>(HashCode32)
            );

            if constexpr (TestBit(HashCode32, 4)) {
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
            result = static_cast<uint64_t>(RnVal) + op2 + instance._status.C() ;
        else if constexpr (opcode == SBC)
            result = static_cast<uint64_t>(RnVal) - op2 + instance._status.C() - 1 ;
        else if constexpr (opcode == RSC)
            result = static_cast<uint64_t>(op2) - RnVal + instance._status.C() - 1 ;
        else if constexpr (opcode == ORR)
            result = static_cast<uint64_t>(RnVal) | op2 ;
        else if constexpr (opcode == MOV)
            result = static_cast<uint64_t>(op2) ;
        else if constexpr (opcode == BIC)
            result = static_cast<uint64_t>(RnVal) & (~op2) ;
        else if constexpr (opcode == MVN)
            result = ~op2 ;

        if constexpr (TestBit(HashCode32, S)) {
            if constexpr (OT == OP_TYPE::LOGICAL) {
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
                shiftCarry ? instance._status.SetC() : instance._status.ClearC() ;;
                result == 0 ? instance._status.SetZ() : instance._status.ClearZ();
            } // if
            else {
                CPSR_Arithmetic<opcode> (instance, RnVal, op2);
                (result & 0xffffffff) == 0 ? instance._status.SetZ() : instance._status.ClearZ() ;
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
            } // else
        } // if

        if constexpr (!TEST) {
            const uint8_t RdNumber = (curInst & 0xf000) >> 12 ;
            instance._status._regs[RdNumber] = result ;
            if (RdNumber == pc) {
                instance.RefillPipeline() ;
                if constexpr (TestBit(HashCode32, S)) {
                    instance._status.WriteCPSR( instance._status.ReadSPSR() ) ;
                } // if
            } // if
        } // if
    }
} // gg_core::gg_cpu

#endif // GGADV_V4_ALU_IMPLEMENT
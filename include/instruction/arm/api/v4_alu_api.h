#include <cstdint>

#ifndef GGADV2_ALU_API_H
#define GGADV2_ALU_API_H

namespace gg_core::gg_cpu {
    // using alu_handler = void(*)(uint32_t&, uint32_t, uint32_t) ;
    enum class OP_TYPE { LOGICAL, ARITHMETIC, TEST } ;

    enum class SHIFT_BY {
        RS, IMM, NONE
    };
    enum class SHIFT_TYPE {
        LSL, LSR, ASR, ROR, NONE
    };

    template <SHIFT_TYPE ST>
    inline bool ParseOp2_Shift_RS(GbaInstance &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RmNumber = curInst & 0b1111 ;
        const uint8_t RsNumber = (curInst & 0xf00) >> 8 ;

        uint32_t Rm = instance._status._regs[ RmNumber ] ;
        uint32_t Rs = instance._status._regs[ RsNumber ] & 0xff ;
        bool carry = false ;

        if (RmNumber == pc)
            Rm = (Rm + 4) ;

        if constexpr (ST == SHIFT_TYPE::LSL) {
            // todo: Does the behavior of shift_by_Rs_eq_zero and shift_by_imm_eq_zero same?
            if (Rs == 0) {
                op2 = Rm ;
                carry = instance._status.C() ;
            } // if
            else if (Rs < 32) {
                op2 = Rm << Rs ;
                carry = TestBit(Rm, 33 - (Rs + 1)) ;
            } // else if
            else {
                op2 = 0 ;
                carry = Rs == 32 && TestBit(Rm, 0);
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::LSR) {
            if (Rs == 0) {
                op2 = Rm ;
                carry = instance._status.C() ;
            } // if
            else if (Rs < 32) {
                op2 = Rm >> Rs ;
                carry = TestBit(Rm, Rs - 1) ;
            } // else if
            else {
                op2 = 0 ;
                carry = Rs == 32 && TestBit(Rm, Rs - 1);
            } // else
        } // if

        if constexpr (ST == SHIFT_TYPE::ASR) {
            if (Rs >= 32) {
                carry = TestBit(Rm, 31) ;
                op2 = carry ? 0xffffffff : 0x0 ;
            } // if
            else {
                op2 = static_cast<int32_t>(Rm) >> Rs ;
                if (Rs != 0)
                    carry = TestBit(Rm, Rs - 1) ;
                else
                    carry = instance._status.C() ;
            } // else if
        } // if

        if constexpr (ST == SHIFT_TYPE::ROR) {
            if (Rs > 32)
                Rs -= 32 ;
            carry = Rs == 0 ? instance._status.C() : TestBit(Rm, Rs - 1) ;
            op2 = rotr(Rm, Rs);
        } // if

        return carry ;
    } // ParseOp2_Shift_RS()

    template <SHIFT_TYPE ST>
    bool ParseOp2_Shift_Imm(GbaInstance &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        uint32_t Rm = instance._status._regs[ curInst & 0b1111 ] ;
        const uint8_t shiftAmount = (curInst & 0xf80) >> 7 ;

        bool carry = false ;
        if constexpr (ST == SHIFT_TYPE::LSL) {
            op2 = Rm << shiftAmount ;
            if (shiftAmount != 0)
                carry = TestBit(Rm, 33 - (shiftAmount + 1)) ;
            else
                carry = instance._status.C() ;
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
                op2 = (instance._status.C() << 31) | (Rm >> 1) ;
            } // if
            else {
                op2 = rotr(Rm, shiftAmount);
                carry = TestBit(Rm, shiftAmount -1) ;
            } // else
        } // if

        return carry ;
    } // ParseOp2_Shift_Imm()

    void ParseOp2_Imm(GbaInstance &instance, uint32_t &op2) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint32_t imm = curInst & 0xff ;
        const uint8_t rot = (curInst & 0xf00) >> 7 ;
        op2 = rotr(imm, rot) ;
    } // ParseOp2_Imm()

    template<bool I, bool S, bool TEST, SHIFT_BY SHIFT_SRC, SHIFT_TYPE ST, OP_TYPE OT, typename F>
    static void Alu_impl(GbaInstance &instance, F operation) requires
        std::is_same_v<std::invoke_result_t<F, unsigned, unsigned, gg_cpu::Status&>, uint64_t>
    {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RnNumber = (curInst & 0xf0000) >> 16 ;

        uint32_t RnVal = instance._status._regs[RnNumber] ;
        uint32_t op2 = 0 ;
        bool shiftCarry = false ;

        if constexpr (I) {
            ParseOp2_Imm(instance, op2) ;
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

        uint64_t result = operation(RnVal, op2, instance._status) ;

        if constexpr (S) {
            if constexpr (OT == OP_TYPE::LOGICAL) {
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
                shiftCarry ? instance._status.SetC() : instance._status.ClearC() ;;
                result == 0 ? instance._status.SetZ() : instance._status.ClearZ();
            } // if
            else {
                const bool RnSigned = TestBit(RnVal, 31);
                const bool op2Signed = TestBit(op2, 31);
                const bool resultSigned = TestBit(result, 31);

//                (RnSigned == op2Signed) && (RnSigned != resultSigned) ? instance._status.SetV() : instance._status.ClearV();
//                result > 0xffffffff ? instance._status.ClearC() : instance._status.SetC() ;
                (result & 0xffffffff) == 0 ? instance._status.SetZ() : instance._status.ClearZ() ;
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
            } // else
        } // if

        if constexpr (!TEST) {
            const uint8_t RdNumber = (curInst & 0xf000) >> 12 ;
            instance._status._regs[RdNumber] = result ;
            if (RdNumber == pc) {
                instance.RefillPipeline() ;
                if constexpr (S) {
                    instance._status.WriteCPSR( instance._status.ReadSPSR() ) ;
                } // if
            } // if
        } // if
    }
}

#endif
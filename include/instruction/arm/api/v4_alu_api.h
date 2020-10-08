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

    bool ParseOp2_Shift_RS(GbaInstance &instance, uint32_t &op2, SHIFT_TYPE ST) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RmNumber = curInst & 0b1111 ;
        const uint8_t RsNumber = (curInst & 0xf00) >> 8 ;

        uint32_t Rm = instance._status._regs[ RmNumber ] ;
        uint32_t Rs = instance._status._regs[ RsNumber ] % 32 ;
        bool carry = false ;

        if (RmNumber == pc)
            Rm += 4 ;
        if (RsNumber == pc)
            Rs += 4 ;

        if (ST == SHIFT_TYPE::LSL) {
            op2 = Rm << Rs ;
            carry = TestBit(Rm, 32 - (Rs + 1)) ;
        } // if

        if (ST == SHIFT_TYPE::LSR) {
            op2 = Rm >> Rs ;
            carry = TestBit(Rm, Rs) ;
        } // if

        if (ST == SHIFT_TYPE::ASR) {
            op2 = static_cast<int32_t>(Rm) >> Rs ;
            carry = TestBit(Rm, Rs) ;
        } // if

        if (ST == SHIFT_TYPE::ROR) {
            op2 = rotr(Rm, Rs) ;
            carry = TestBit(Rm, Rs) ;
        } // if

        return carry ;
    } // ParseOp2_Shift_RS()

    bool ParseOp2_Shift_Imm(GbaInstance &instance, uint32_t &op2, SHIFT_TYPE ST) {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        uint32_t Rm = instance._status._regs[ curInst & 0b1111 ] ;
        const uint8_t shiftAmount = (curInst & 0xf80) >> 7 ;

        bool carry = false ;
        if (ST == SHIFT_TYPE::LSL) {
            op2 = Rm << shiftAmount ;
            if (shiftAmount != 0)
                carry = TestBit(Rm, 32 - (shiftAmount + 1)) ;
            else
                carry = instance._status.C() ;
        } // if

        if (ST == SHIFT_TYPE::LSR) {
            if (shiftAmount == 0) {
                op2 = 0 ;
                carry = TestBit(Rm, 31) ;
            } // if
            else {
                op2 = Rm >> shiftAmount ;
                carry = TestBit(Rm, shiftAmount) ;
            } // else
        } // if

        if (ST == SHIFT_TYPE::ASR) {
            if (shiftAmount == 0) {
                carry = TestBit(Rm, 31) ;
                op2 = carry ? 0xffffffff : 0x0 ;
            } // if
            else {
                op2 = static_cast<int32_t>(Rm) >> shiftAmount ;
                carry = TestBit(Rm, shiftAmount) ;
            } // else
        } // if

        if (ST == SHIFT_TYPE::ROR) {
            if (shiftAmount == 0) {
                // RRX
                carry = TestBit(Rm, 0) ;
                op2 = (instance._status.C() << 31) | (Rm >> 1) ;
            } // if
            else {
                op2 = rotr(Rm, shiftAmount);
                carry = TestBit(Rm, shiftAmount) ;
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

    template <typename F>
    static void Alu_impl(GbaInstance &instance, F operation, OP_TYPE OT) requires
        std::is_same_v<std::invoke_result_t<F, unsigned, unsigned, bool>, uint64_t>
    {
        const uint32_t curInst = CURRENT_INSTRUCTION ;
        const uint8_t RnNumber = (curInst & 0xf0000) >> 16 ;

        uint32_t& Rn = instance._status._regs[RnNumber] ;
        uint32_t op2 = 0 ;
        bool shiftCarry = false ;

        if (TestBit(CURRENT_INSTRUCTION, 25)) {
            ParseOp2_Imm(instance, op2) ;
        } // if
        else {
            uint32_t st = BitFieldValue<uint32_t, 5, 2>(CURRENT_INSTRUCTION) ;
            if (TestBit(CURRENT_INSTRUCTION, 4)) {
                if (RnNumber == pc)
                    Rn += 4 ;
                shiftCarry = ParseOp2_Shift_RS(
                        instance,
                        op2,
                        static_cast<SHIFT_TYPE>(st) );
            } // if
            else
                shiftCarry = ParseOp2_Shift_Imm(instance, op2, static_cast<SHIFT_TYPE>(st)) ;
        } // else

        uint64_t result = operation(Rn, op2, instance._status.C()) ;

        if (TestBit(CURRENT_INSTRUCTION, 20)) {
            if (OT == OP_TYPE::LOGICAL || OT == OP_TYPE::TEST) {
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
                shiftCarry ? instance._status.SetC() : instance._status.ClearC() ;;
                result == 0 ? instance._status.SetZ() : instance._status.ClearZ();
            } // if
            else {
                const bool RnSigned = TestBit(Rn, 31);
                const bool op2Signed = TestBit(op2, 31);
                const bool resultSigned = TestBit(result, 31);

                (RnSigned == op2Signed) && (RnSigned != resultSigned) ? instance._status.SetV() : instance._status.ClearV();
                result > 0xffffffff ? instance._status.SetC() : instance._status.ClearC() ;
                (result & 0xffffffff) == 0 ? instance._status.SetZ() : instance._status.ClearZ() ;
                TestBit(result, 31) ? instance._status.SetN() : instance._status.ClearN() ;
            } // else
        } // if

        if (OT != OP_TYPE::TEST) {
            const uint8_t RdNumber = (curInst & 0xf000) >> 12 ;
            instance._status._regs[RdNumber] = result ;
            if (RdNumber == pc) {
                instance.RefillPipeline() ;
                if (TestBit(CURRENT_INSTRUCTION, 20)) {
                    instance._status.WriteCPSR( instance._status.ReadSPSR() ) ;
                } // if
            } // if
        } // if
    }
}

#endif
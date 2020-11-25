#include <bit_manipulate.h>
#include <cstdint>

namespace gg_core::gg_cpu {
    enum class OP_TYPE { LOGICAL, ARITHMETIC, TEST } ;

    enum class SHIFT_BY {
        RS, IMM, NONE
    };
    enum class SHIFT_TYPE {
        LSL, LSR, ASR, ROR, NONE
    };

    template <SHIFT_TYPE ST>
    bool ParseOp2_Shift_RS(GbaInstance &instance, uint32_t &op2) {
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
            Rs %= 32 ;
            op2 = rotr(Rm, Rs) ;
            if (Rs != 0)
                carry = TestBit(Rm, Rs - 1) ;
            else
                carry = instance._status.C() ;
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

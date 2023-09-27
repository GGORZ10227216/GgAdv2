#include <type_traits>
#include <cstdint>

#include <v4_operand2.h>
#include <bit_manipulate.h>

#ifndef GGADV2_ALU_API_H
#define GGADV2_ALU_API_H

namespace gg_core::gg_cpu {
// using alu_handler = void(*)(uint32_t&, uint32_t, uint32_t) ;
template<E_DataProcess opcode>
inline void CPSR_Arithmetic(CPU &instance, uint32_t Rn, uint32_t op2, uint64_t result) {
  bool needSetCarry = false, needSetOverflow = false;
  if constexpr (opcode == ADD || opcode == CMN || opcode == ADC) {
	needSetOverflow = TestBit(Rn, 31) == TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31);
	needSetCarry = result > 0xffffffff;
  } // if
  else if constexpr (opcode == SUB || opcode == CMP) {
	needSetOverflow = TestBit(Rn, 31) != TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31);
	needSetCarry = static_cast<uint64_t>(Rn) >= op2;
  } // else if
  else if constexpr (opcode == SBC) {
	needSetOverflow = TestBit(Rn, 31) != TestBit(op2, 31) && TestBit(Rn, 31) != TestBit(result, 31);
	needSetCarry = static_cast<uint64_t>(Rn) >= static_cast<uint64_t>(op2) - instance.C() + 1;
  } // else if
  else if constexpr (opcode == RSB) {
	needSetOverflow = TestBit(op2, 31) != TestBit(Rn, 31) && TestBit(op2, 31) != TestBit(result, 31);
	needSetCarry = static_cast<uint64_t>(op2) >= Rn;
  } // else if
  else if constexpr (opcode == RSC) {
	needSetOverflow = TestBit(op2, 31) != TestBit(Rn, 31) && TestBit(op2, 31) != TestBit(result, 31);
	needSetCarry = static_cast<uint64_t>(op2) >= static_cast<uint64_t>(Rn) - instance.C() + 1;
  } // else if

  needSetOverflow ? instance.SetV() : instance.ClearV();
  needSetCarry ? instance.SetC() : instance.ClearC();
}

template<bool S, E_DataProcess opcode>
static int ALU_Calculate(CPU &instance, uint32_t arg1, uint32_t arg2, bool shiftCarry) {
  constexpr enum OP_TYPE OT = (opcode >= SUB && opcode <= RSC) || (opcode == CMP || opcode == CMN) ?
							  OP_TYPE::ARITHMETIC : OP_TYPE::LOGICAL;
  uint64_t result = 0;

  if constexpr (opcode == AND || opcode == TST)
	result = static_cast<uint64_t>(arg1) & arg2;
  else if constexpr (opcode == EOR || opcode == TEQ)
	result = static_cast<uint64_t>(arg1) ^ arg2;
  else if constexpr (opcode == SUB || opcode == CMP)
	result = static_cast<uint64_t>(arg1) - arg2;
  else if constexpr (opcode == RSB)
	result = static_cast<uint64_t>(arg2) - arg1;
  else if constexpr (opcode == ADD || opcode == CMN)
	result = static_cast<uint64_t>(arg1) + arg2;
  else if constexpr (opcode == ADC)
	result = static_cast<uint64_t>(arg1) + arg2 + instance.C();
  else if constexpr (opcode == SBC)
	result = static_cast<uint64_t>(arg1) - arg2 + instance.C() - 1;
  else if constexpr (opcode == RSC)
	result = static_cast<uint64_t>(arg2) - arg1 + instance.C() - 1;
  else if constexpr (opcode == ORR)
	result = static_cast<uint64_t>(arg1) | arg2;
  else if constexpr (opcode == MOV)
	result = static_cast<uint64_t>(arg2);
  else if constexpr (opcode == BIC)
	result = static_cast<uint64_t>(arg1) & (~arg2);
  else if constexpr (opcode == MVN)
	result = ~arg2;

  if constexpr (S) {
	if constexpr (OT == OP_TYPE::LOGICAL) {
	  TestBit(result, 31) ? instance.SetN() : instance.ClearN();
	  shiftCarry ? instance.SetC() : instance.ClearC();
	  result == 0 ? instance.SetZ() : instance.ClearZ();
	} // if
	else {
	  CPSR_Arithmetic<opcode>(instance, arg1, arg2, result);
	  (result & 0xffffffff) == 0 ? instance.SetZ() : instance.ClearZ();
	  TestBit(result, 31) ? instance.SetN() : instance.ClearN();
	} // else
  } // if

  return result;
}

template<typename T, bool S, SHIFT_BY SHIFT_SRC, E_DataProcess opcode>
static void ALU_OperationImpl(CPU &instance,
							  const int dstReg,
							  const int op1Reg,
							  const uint32_t op2Val,
							  const bool shiftCarry) {
  /*
   * There are 4 different code flow for this function. each of them will lead to different cycle count result:
   *   1. Normal Data Processing:
   *     flow: E, cycle: 1S
   *   2. Data Processing with register specified shift:
   *     flow: A -> C, cycle: 1I + 1S
   *   3. Data Processing with PC written:
   *     flow: D -> F, cycle: 1N + 2S
   *   4. Data Processing with PC written and register specified shift:
   *     flow: A -> B -> F, cycle: 1I + 1N + 2S
   * */

  constexpr bool TEST = opcode == TST || opcode == TEQ || opcode == CMP || opcode == CMN;
  if constexpr (SHIFT_SRC == SHIFT_BY::RS) {
	/*A*/ instance.Fetch(&instance, gg_mem::I_Cycle); // pc = pc + 4

	// We are performing a memory read here, but discard the result.
	// This is because our purpose is to increase the cycle counter.
	// Check the ARM7TDMI manual(page 231, shift(Rs) part) for more information.
	if (dstReg == pc) {
	  /*B*/ instance._mem.Read<T>(instance._regs[ pc ] + 4, gg_mem::N_Cycle);
	} // if
	else {
	  /*C*/ instance._mem.Read<T>(instance._regs[ pc ] + 4, gg_mem::S_Cycle);
	} // else
  } // if constexpr
  else {
	if (dstReg == pc)
	  /*D*/ instance.Fetch(&instance, gg_mem::N_Cycle);
	else
	  /*E*/ instance.Fetch(&instance, gg_mem::S_Cycle);
  } // else

  uint32_t op1Val = instance._regs[op1Reg];

  if constexpr (SHIFT_SRC == SHIFT_BY::RS) {
	// If we read PC now, we will get the PC + 3L value.
	// But, strangely, the value inside the register seems to be PC + 8.
	if (op1Reg == pc)
	  op1Val = op1Val + instance.instructionLength ;
  } // if constexpr

  uint64_t result = ALU_Calculate<S, opcode>(instance, op1Val, op2Val, shiftCarry);

  if constexpr (!TEST) {
	instance._regs[dstReg] = result;
	if (dstReg == pc) {
	  /*F*/ instance.RefillPipeline(&instance, gg_mem::S_Cycle, gg_mem::S_Cycle); // cycle += 1S + 1S
	  if constexpr (S) {
		instance.WriteCPSR(instance.ReadSPSR());
	  } // if
	} // if
  } // if
}

template<bool I, bool S, SHIFT_BY SHIFT_SRC, E_ShiftType ST, E_DataProcess opcode>
static void ALU_ARM_Operation(CPU &instance) {
  const uint32_t curInst = CURRENT_INSTRUCTION;

  const uint8_t RnNumber = (curInst & 0xf0000) >> 16;
  const uint8_t RdNumber = (curInst & 0xf000) >> 12;

  bool shiftCarry = false;
  uint32_t op2 = 0;

  if constexpr (I) {
	shiftCarry = ParseOp2_Imm(instance, op2);
  } // if
  else {
	if constexpr (SHIFT_SRC == SHIFT_BY::RS) {
	  shiftCarry = ParseOp2_Shift_RS<ST>(instance, op2);
	} // if
	else
	  shiftCarry = ParseOp2_Shift_Imm<ST>(instance, op2);
  } // else

  ALU_OperationImpl<uint32_t, S, SHIFT_SRC, opcode>(instance, RdNumber, RnNumber, op2, shiftCarry);
}
}

#endif
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
static int ALU_Calculate(CPU &instance, uint32_t arg1, uint32_t arg2, const bool carryResult) {
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
	  carryResult ? instance.SetC() : instance.ClearC();
	  TestBit(result, 31) ? instance.SetN() : instance.ClearN();
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

template<typename T, bool S, E_DataProcess opcode>
static void ALU_Execute(CPU &instance,
						const unsigned RdNumber,
						const uint32_t op1Val,
						const uint32_t op2Val,
						const bool carryResult)
{
  constexpr bool TEST = opcode == TST || opcode == TEQ || opcode == CMP || opcode == CMN;
  uint64_t result = ALU_Calculate<S, opcode>(instance, op1Val, op2Val, carryResult);

  if constexpr (!TEST) {
	instance._regs[RdNumber] = result;
	if (RdNumber == pc) {
	  if constexpr (S) {
		instance.WriteCPSR(instance.ReadSPSR());
	  } // if

	  /*F*/ instance.RefillPipeline(&instance, gg_mem::N_Cycle, gg_mem::S_Cycle);
	} // if
  } // if
} // ALU_Execute()

//template <SHIFT_BY SHIFT_SRC>
//void ALU_Fetch(CPU &instance, const unsigned RdNumber) {
//  if constexpr (SHIFT_SRC == SHIFT_BY::REG) {
//	// We are performing a memory read here, but discard the result.
//	// This is because our purpose is to increase the cycle counter.
//	// Check the ARM7TDMI manual(page 231, shift(Rs) part) for more information.
//	instance.Fetch(&instance, gg_mem::I_Cycle); /*A*/
//	if (RdNumber == pc) {
//	  /*B*/ instance._mem.Read<uint32_t>(instance._regs[pc] + 4, gg_mem::N_Cycle);
//	} // if
//	else {
//	  /*C*/ instance._mem.Read<uint32_t>(instance._regs[pc] + 4, gg_mem::S_Cycle);
//	} // else
//  } // if constexpr
//  else {
//	if (RdNumber == pc)
//	  /*D*/ instance.Fetch(&instance, gg_mem::N_Cycle);
//	else
//	  /*E*/ instance.Fetch(&instance, gg_mem::S_Cycle);
//  } // else
//} // ALU_Fetch()

template <SHIFT_BY SHIFT_SRC, E_ShiftType ST>
void ALU_CalculateShiftOp2(CPU &instance, const unsigned shiftBaseRegNumber, const unsigned shiftAmount, uint32_t &op2, bool &carryResult) {
  if constexpr (SHIFT_SRC == SHIFT_BY::REG) {
	if (shiftBaseRegNumber == pc)
	  instance._regs[shiftBaseRegNumber] += instance.instructionLength;
	Op2ShiftReg<ST>(instance, instance._regs[shiftBaseRegNumber], shiftAmount, op2, carryResult);
	instance.Idle();
  } // if
  else {
	Op2ShiftImm<ST>(instance, instance._regs[shiftBaseRegNumber], shiftAmount, op2, carryResult);
  } // else
} // ALU_CalculateOp2()

void ALU_CalculateImmOp2(CPU &instance, const unsigned imm, const unsigned rot, uint32_t &op2, bool &carryResult) {
  op2 = rotr(imm, rot);
  if (rot != 0)
	carryResult = TestBit(op2, 31); // CPU seems to be reusing the barrel shifter for immediate rotate
  else
	carryResult = instance.C();
} // ALU_CalculateImmOp2()

template<bool I, bool S, SHIFT_BY SHIFT_SRC, E_ShiftType ST, E_DataProcess opcode>
static void ALU_ARM_Operation(CPU &instance) {
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
  const uint32_t curInst = CURRENT_INSTRUCTION;

  const uint8_t RnNumber = (curInst & 0xf0000) >> 16;
  const uint8_t RdNumber = (curInst & 0xf000) >> 12;

  bool carryResult = false;
  uint32_t op2 = 0;

//  ALU_Fetch<SHIFT_SRC>(instance, RdNumber);

  if constexpr (!I) {
	unsigned shiftAmount;
	const uint8_t RmNumber = curInst & 0b1111;

	if constexpr (SHIFT_SRC == SHIFT_BY::REG) {
	  const uint8_t RsNumber = (curInst & 0xf00) >> 8;
	  shiftAmount = instance._regs[RsNumber];
	} // if constexpr
	else {
	  shiftAmount = (curInst & 0xf80) >> 7;
	} // else

	ALU_CalculateShiftOp2<SHIFT_SRC, ST>(instance, RmNumber, shiftAmount, op2, carryResult);
  } // if
  else {
	const uint32_t imm = curInst & 0xff;
	// (curInst >> 8) << 1, please refer to ARM7TDMI manual
	// 4.5.3 Immediate operand rotates, "twice the value in the rotate field" part
	const uint8_t rot = (curInst & 0xf00) >> 7;

	ALU_CalculateImmOp2(instance, imm, rot, op2, carryResult);
  } // if constexpr

  ALU_Execute<uint32_t, S, opcode>(instance, RdNumber, instance._regs[RnNumber], op2, carryResult);
}
}

#endif
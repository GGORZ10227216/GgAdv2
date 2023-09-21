//
// Created by Jason4_Lee on 2021-08-24.
//

#include <thumb/decoder/type4.h>

namespace {
using namespace gg_core::gg_cpu;

void CalleeCheek(CPU &local_cpu, const unsigned Op) {
  switch (Op) {
  case 0:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<AND>);
	break;
  case 1:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<EOR>);
	break;
  case 2:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<LSL>);
	break;
  case 3:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<LSR>);
	break;
  case 4:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<ASR>);
	break;
  case 5:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<ADC>);
	break;
  case 6:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<SBC>);
	break;
  case 7:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<ROR>);
	break;
  case 8:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<TST>);
	break;
  case 9:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<RSB>);
	break;
  case 10:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<CMP>);
	break;
  case 11:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<CMN>);
	break;
  case 12:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<ORR>);
	break;
  case 13:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<0>); // MUL
	break;
  case 14:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<BIC>);
	break;
  case 15:ASSERT_TRUE(local_cpu.lastCallee == ALU_Operations<MVN>);
	break;
  default:throw std::logic_error("Invalid Op number");
  } // switch
} // Op2Shift()

TEST_F(ggTest, ALU_Operation) {
  auto TestMain = [&](const unsigned Op, const uint32_t RsValue, const uint32_t RdValue) -> uint64_t {
	uint64_t t = 0;

	Arm egg_local;
	egg_local.flushHalf();
	egg_local.cpsr.t = true;

	gg_core::GbaInstance instance_local;
	gg_core::gg_cpu::CPU &local_cpu = instance_local.cpu;
	GgInitToThumbState(local_cpu);

	auto task = [&]() {
	  for (int RsNum = 0; RsNum < 8; ++RsNum) {
		for (int RdNum = 0; RdNum < 8; ++RdNum) {
		  uint16_t instruction = (0b010000 << 10) | (Op << 6) | (RsNum << 3) | RdNum;

		  egg_local.regs[RsNum] = RsValue;
		  local_cpu._regs[RsNum] = RsValue;

		  egg_local.regs[RdNum] = RdValue;
		  local_cpu._regs[RdNum] = RdValue;

		  EggRunThumb(egg_local, instruction);
		  local_cpu.CPU_Test(instruction);

		  uint32_t errFlag = CheckStatus(local_cpu, egg_local);
		  std::string input = fmt::format("Original Rd(R{}): {:#x} Rs(R{}): {:#x}\n",
										  RdNum, RdValue, RsNum, RsValue);

		  CalleeCheek(local_cpu, Op);

		  ASSERT_TRUE(errFlag == 0)
					  << "#" << t << " of test\n"
					  << std::hex << "Errflag: " << errFlag << '\n'
					  << input
					  << gg_tasm.DASM(instruction) << " [" << instruction
					  << "]" << '\n'
					  << Diagnose(local_cpu, egg_local, errFlag);

		  CpuPC_Reset(egg_local, local_cpu);
		  ++t;
		} // for
	  } // for
	};

	task();
	fmt::print("[{}] Op: {:#x} {}\n", std::this_thread::get_id(), Op, t);
	return t;
  };

  boost::asio::thread_pool workerPool(std::thread::hardware_concurrency());
  for (int OpTest = 0; OpTest < 16; ++OpTest) {
	for (int RsTest = 0; RsTest < 16; ++RsTest) {
	  for (int RdTest = 0; RdTest < 16; ++RdTest) {
		uint32_t RsValue = 0x01010101 * RsTest;
		uint32_t RdValue = 0x01010101 * RdTest;

		boost::asio::post(workerPool,
						  [TestMain, OpTest, RsValue, RdValue] {
							return TestMain(OpTest, RsValue, RdValue);
						  } // lambda
		);

		if (RsValue != 0) {
		  boost::asio::post(workerPool,
							[TestMain, OpTest, RsValue, RdValue] {
							  return TestMain(OpTest, RsValue << 4, RdValue);
							} // lambda
		  );
		} // if

		if (RdValue != 0) {
		  boost::asio::post(workerPool,
							[TestMain, OpTest, RsValue, RdValue] {
							  return TestMain(OpTest, RsValue, RdValue << 4);
							} // lambda
		  );
		} // if

		if (RdValue != 0 && RsValue != 0) {
		  boost::asio::post(workerPool,
							[TestMain, OpTest, RsValue, RdValue] {
							  return TestMain(OpTest, RsValue << 4, RdValue << 4);
							} // lambda
		  );
		} // if
	  } // for
	} // for
  } // for

  workerPool.join();
}
}

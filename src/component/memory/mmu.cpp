//
// Created by orzgg on 2021-12-02.
//

#include <gba_instance.h> // GbaInstance, MMU

namespace gg_core::gg_mem {
void IO_DirectWrite(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  // TODO: I/O reg write log.
//  std::cerr << "Illegal I/O reg write, offset: 0x" << std::hex << relativeAddr << std::endl;
  if (relativeAddr == gg_io::OFFSET_DISPSTAT)
	data &= 0x3f;
  instance.mmu.IOReg[relativeAddr] = data;
} // IO_IllegalWrite()

MMU_Status::MMU_Status(GbaInstance &instance, const std::optional<std::filesystem::path> &romPath) :
	cartridge(_elapsedCycle),
	_cpuStatus(instance.cpu)
{
  if (romPath.has_value())
	cartridge.LoadRom(romPath.value());
  else {
//	logger->warn("Emulator is working under DEBUG mode(no ROM loaded!!)");
  } // else
}

MMU::MMU(GbaInstance &instance, const std::optional<std::filesystem::path> &romPath) :
	MMU_Status(instance, romPath),
	_instance(instance)
{
  memcpy(bios_data.data(), biosData.data(), biosData.size());
  ioWriteHandlerTable.fill(IO_DirectWrite);

//  (uint16_t&)IOReg[gg_io::OFFSET_DISPCNT] = 0x80;
  (uint16_t&)IOReg[gg_io::OFFSET_BG2PA] = 0x100;
  (uint16_t&)IOReg[gg_io::OFFSET_BG3PA] = 0x100;
  (uint16_t&)IOReg[gg_io::OFFSET_BG2PD] = 0x100;
  (uint16_t&)IOReg[gg_io::OFFSET_BG2PD] = 0x100;
  (uint16_t&)IOReg[gg_io::OFFSET_SOUNDBIAS] = 0x200;
  (uint16_t&)IOReg[gg_io::OFFSET_KEYINPUT] = 0x3ff; // All key released by default.
}

void MMU::FifoWrite(const unsigned int channelIdx, const uint32_t data) {
  // Normally, the FIFO length should be 4 * 32bit = 16byte.(according to fifo DMA's design)
  // But GBATEK says that the FIFO buffer can buffer 8 * 32bit(32byte) data.
  auto &apu = _instance.apu;
  apu.PushFifo(channelIdx, data);
} // FifoWrite()

[[nodiscard]] uint32_t MMU_Status::IllegalReadValue() {
  using namespace gg_cpu;

  if (_cpuStatus.GetCpuMode() == gg_cpu::E_CpuMode::ARM)
	return _cpuStatus.fetchedBuffer[_cpuStatus.fetchIdx];
  else {
	const uint32_t CPU_PC = _cpuStatus._regs[pc];
	enum {
	  BIOS_AREA = 0, IRAM_AREA = 3, OAM_AREA = 7
	};

	uint32_t result = 0;
	const uint32_t lastFetch = _cpuStatus.fetchedBuffer[!_cpuStatus.fetchIdx];
	const uint32_t thisFetch = _cpuStatus.fetchedBuffer[_cpuStatus.fetchIdx];
	const unsigned addrTrait = CPU_PC >> 24;

	switch (addrTrait) {
	  case BIOS_AREA:
	  case OAM_AREA:
		// Wait, Wat? [PC + 6] is outside the pipeline!!
		// using PC + 4 for now, just like mgba does.
		result = (thisFetch << 16) | lastFetch;
		break;
	  case IRAM_AREA:
		if (CPU_PC & 2)
		  result = (thisFetch << 16) | lastFetch;
		else
		  result = (lastFetch << 16) | thisFetch;
		break;
	  default:result = (thisFetch << 16) | thisFetch;
	} // switch()

	return result;
  } // else
} // IllegalReadValue()

void MMU_Status::UpdateWaitState() {
  enum { N = 0, S = 1 };
  const uint16_t WAITCNT = IOReg[0x204];

  // wc == wait_control
  const unsigned wc_sram = WAITCNT & 0b11;

  // SRAM allow byte access only
  memCycleTable[N][E_SRAM].byte = N_CYCLE_TABLE[wc_sram] + 1;

  const unsigned wc_ws0_n = (WAITCNT & 0b1100) >> 2;
  const unsigned wc_ws0_s = TestBit(WAITCNT, 4);
  memCycleTable[N][E_WS0].byte = N_CYCLE_TABLE[wc_ws0_n] + 1;
  memCycleTable[N][E_WS0].word = N_CYCLE_TABLE[wc_ws0_n] + 1;
  memCycleTable[N][E_WS0].dword = N_CYCLE_TABLE[wc_ws0_n] + 1 + S_CYCLE_TABLE[wc_ws0_s] + 1;
  memCycleTable[N][E_WS0_B] = memCycleTable[N][E_WS0];

  memCycleTable[S][E_WS0].byte = S_CYCLE_TABLE[wc_ws0_s] + 1;
  memCycleTable[S][E_WS0].word = S_CYCLE_TABLE[wc_ws0_s] + 1;
  memCycleTable[S][E_WS0].dword = (S_CYCLE_TABLE[wc_ws0_s] + 1) * 2;
  memCycleTable[S][E_WS0_B] = memCycleTable[S][E_WS0];

  const unsigned wc_ws1_n = (WAITCNT & 0b1100000) >> 5;
  const unsigned wc_ws1_s = TestBit(WAITCNT, 7) + 2;
  memCycleTable[N][E_WS1].byte = N_CYCLE_TABLE[wc_ws1_n] + 1;
  memCycleTable[N][E_WS1].word = N_CYCLE_TABLE[wc_ws1_n] + 1;
  memCycleTable[N][E_WS1].dword = N_CYCLE_TABLE[wc_ws1_n] + 1 + S_CYCLE_TABLE[wc_ws1_s] + 1;
  memCycleTable[N][E_WS1_B] = memCycleTable[N][E_WS1];

  memCycleTable[S][E_WS1].byte = S_CYCLE_TABLE[wc_ws1_s] + 1;
  memCycleTable[S][E_WS1].word = S_CYCLE_TABLE[wc_ws1_s] + 1;
  memCycleTable[S][E_WS1].dword = (S_CYCLE_TABLE[wc_ws1_s] + 1) * 2;
  memCycleTable[S][E_WS1_B] = memCycleTable[S][E_WS1];

  const unsigned wc_ws2_n = (WAITCNT & 0b1100000000) >> 8;
  const unsigned wc_ws2_s = TestBit(WAITCNT, 10) + 4;
  memCycleTable[N][E_WS2].byte = N_CYCLE_TABLE[wc_ws2_n] + 1;
  memCycleTable[N][E_WS2].word = N_CYCLE_TABLE[wc_ws2_n] + 1;
  memCycleTable[N][E_WS2].dword = N_CYCLE_TABLE[wc_ws2_n] + 1 + S_CYCLE_TABLE[wc_ws2_s] + 1;
  memCycleTable[N][E_WS2_B] = memCycleTable[N][E_WS2];

  memCycleTable[S][E_WS2].byte = S_CYCLE_TABLE[wc_ws2_s] + 1;
  memCycleTable[S][E_WS2].word = S_CYCLE_TABLE[wc_ws2_s] + 1;
  memCycleTable[S][E_WS2].dword = (S_CYCLE_TABLE[wc_ws2_s] + 1) * 2;
  memCycleTable[S][E_WS2_B] = memCycleTable[S][E_WS2];
} // UpdateWaitState()

void MMU::RegisterIOHandler(const std::vector<std::pair<gg_io::E_IO_OFFSET, IOWriteHandler>> &handlerList) {
  using namespace gg_io;

  for (const auto& [offset, handler] : handlerList) {
	if ((uint32_t)offset < gg_mem::E_IO_SIZE) {
	  const auto regAccessMode = (E_IO_AccessMode)policyTable[offset];
	  if (regAccessMode == gg_io::E_IO_AccessMode::R || regAccessMode == gg_io::E_IO_AccessMode::U) {
		std::cerr << "Try to register a I/O reg write handler to a non-writable address, offset: 0x"
		          << std::hex << offset << std::endl;
		exit(-1);
	  } // if

	  const unsigned regWidth = offset == OFFSET_POSTFLG || offset == OFFSET_HALTCNT ? 1 : 2;

	  for (unsigned i = 0; i < regWidth ; ++i) {
		ioWriteHandlerTable[offset + i] = handler;
	  } // for
	} // if
	else {
	  std::cerr << "Try to register a I/O write handler to an invalid address, offset: 0x"
	            << std::hex << offset << std::endl;
	  exit(-1);
	} // else
  } // for
} // RegisterIOHandler()

void MMU::AddCycle(const uint32_t absAddr, const E_AccessType accessType, const unsigned accessWide, const char* comment) {
  const unsigned deltaClk = CalculateCycle(absAddr, accessWide, accessType);
  _instance.Follow(deltaClk);
} // AddCycle()
}
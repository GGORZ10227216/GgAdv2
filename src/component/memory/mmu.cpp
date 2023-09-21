//
// Created by orzgg on 2021-12-02.
//

#include <gba_instance.h>
#include <cpu_enum.h>

#include <handler/bios_handler.h>
#include <handler/ewram_handler.h>
#include <handler/iwram_handler.h>
#include <handler/io_handler.h>
#include <handler/palette_handler.h>
#include <handler/vram_handler.h>
#include <handler/oam_handler.h>
#include <handler/gamepak_handler.h>
#include <handler/sram_handler.h>

namespace gg_core::gg_mem {
MMU_Status::MMU_Status(GbaInstance &instance, const std::optional<std::filesystem::path> &romPath) :
	cartridge(_cycleCounter, instance.logSink),
	_cpuStatus(instance.cpu),
	logger(std::make_shared<spdlog::logger>("MMU", instance.logSink)) {
  if (romPath.has_value())
	cartridge.LoadRom(romPath.value());
  else {
	logger->warn("Emulator is working under DEBUG mode(no ROM loaded!!)");
  } // else
}

MMU::MMU(GbaInstance &instance, const std::optional<std::filesystem::path> &romPath) :
	MMU_Status(instance, romPath),
	_instance(instance) {
  memcpy(bios_data.data(), biosData.data(), biosData.size());
}

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

  memCycleTable[N][E_SRAM].byte = N_CYCLE_TABLE[wc_sram] + 1; // only use this

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

std::array<ReadHandler, 16> MMU::ReadHandlers{
	/*0x0 BIOS*/      ReadHandler(BIOS_Read<uint8_t>, BIOS_Read<uint16_t>, BIOS_Read<uint32_t>),
	/*0x1 NO USED*/   ReadHandler(NoUsed_Read<uint8_t>, NoUsed_Read<uint16_t>, NoUsed_Read<uint32_t>),
	/*0x2 EWRAM*/     ReadHandler(EWRAM_Read<uint8_t>, EWRAM_Read<uint16_t>, EWRAM_Read<uint32_t>),
	/*0x3 IWRAM*/     ReadHandler(IWRAM_Read<uint8_t>, IWRAM_Read<uint16_t>, IWRAM_Read<uint32_t>),
	/*0x4 IO*/        ReadHandler(IO_Read<uint8_t>, IO_Read<uint16_t>, IO_Read<uint32_t>),
	/*0x5 Palette*/   ReadHandler(Palette_Read<uint8_t>, Palette_Read<uint16_t>, Palette_Read<uint32_t>),
	/*0x6 VRAM*/      ReadHandler(VRAM_Read<uint8_t>, VRAM_Read<uint16_t>, VRAM_Read<uint32_t>),
	/*0x7 OAM*/       ReadHandler(OAM_Read<uint8_t>, OAM_Read<uint16_t>, OAM_Read<uint32_t>),
	/*0x8 GAMEPAK_0*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS0>,
								 GAMEPAK_Read<uint16_t, E_WS0>,
								 GAMEPAK_Read<uint32_t, E_WS0>),
	/*0x9 GAMEPAK_0*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS0>,
								 GAMEPAK_Read<uint16_t, E_WS0>,
								 GAMEPAK_Read<uint32_t, E_WS0>),
	/*0xA GAMEPAK_1*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS1>,
								 GAMEPAK_Read<uint16_t, E_WS1>,
								 GAMEPAK_Read<uint32_t, E_WS1>),
	/*0xB GAMEPAK_1*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS1>,
								 GAMEPAK_Read<uint16_t, E_WS1>,
								 GAMEPAK_Read<uint32_t, E_WS1>),
	/*0xC GAMEPAK_2*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS2>,
								 GAMEPAK_Read<uint16_t, E_WS2>,
								 GAMEPAK_Read<uint32_t, E_WS2>),
	/*0xD GAMEPAK_2*/ReadHandler(GAMEPAK_Read<uint8_t, E_WS2>,
								 GAMEPAK_Read<uint16_t, E_WS2>,
								 GAMEPAK_Read<uint32_t, E_WS2>),
	/*0xE SRAM*/ReadHandler(GAMEPAK_Read<uint8_t, E_SRAM>,
							GAMEPAK_Read<uint16_t, E_SRAM>,
							GAMEPAK_Read<uint32_t, E_SRAM>),
	/*0xF SRAM_MIRROR*/ReadHandler(GAMEPAK_Read<uint8_t, E_SRAM>,
								   GAMEPAK_Read<uint16_t, E_SRAM>,
								   GAMEPAK_Read<uint32_t, E_SRAM>)
};

std::array<WriteHandler, 16> MMU::WriteHandlers{
	/*0x0 BIOS*/      WriteHandler(BIOS_Write<uint8_t>, BIOS_Write<uint16_t>, BIOS_Write<uint32_t>),
	/*0x1 NO USED*/   WriteHandler(NoUsed_Write<uint8_t>, NoUsed_Write<uint16_t>, NoUsed_Write<uint32_t>),
	/*0x2 EWRAM*/     WriteHandler(EWRAM_Write<uint8_t>, EWRAM_Write<uint16_t>, EWRAM_Write<uint32_t>),
	/*0x3 IWRAM*/     WriteHandler(IWRAM_Write<uint8_t>, IWRAM_Write<uint16_t>, IWRAM_Write<uint32_t>),
	/*0x4 IO*/        WriteHandler(IO_Write<uint8_t>, IO_Write<uint16_t>, IO_Write<uint32_t>),
	/*0x5 Palette*/   WriteHandler(Palette_Write<uint8_t>, Palette_Write<uint16_t>, Palette_Write<uint32_t>),
	/*0x6 VRAM*/      WriteHandler(VRAM_Write<uint8_t>, VRAM_Write<uint16_t>, VRAM_Write<uint32_t>),
	/*0x7 OAM*/       WriteHandler(OAM_Write<uint8_t>, OAM_Write<uint16_t>, OAM_Write<uint32_t>),
	/*0x8 GAMEPAK_0*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS0>,
								  GAMEPAK_Write<uint16_t, E_WS0>,
								  GAMEPAK_Write<uint32_t, E_WS0>),
	/*0x9 GAMEPAK_0*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS0>,
								  GAMEPAK_Write<uint16_t, E_WS0>,
								  GAMEPAK_Write<uint32_t, E_WS0>),
	/*0xA GAMEPAK_1*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS1>,
								  GAMEPAK_Write<uint16_t, E_WS1>,
								  GAMEPAK_Write<uint32_t, E_WS1>),
	/*0xB GAMEPAK_1*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS1>,
								  GAMEPAK_Write<uint16_t, E_WS1>,
								  GAMEPAK_Write<uint32_t, E_WS1>),
	/*0xC GAMEPAK_2*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS2>,
								  GAMEPAK_Write<uint16_t, E_WS2>,
								  GAMEPAK_Write<uint32_t, E_WS2>),
	/*0xD GAMEPAK_2*/WriteHandler(GAMEPAK_Write<uint8_t, E_WS2>,
								  GAMEPAK_Write<uint16_t, E_WS2>,
								  GAMEPAK_Write<uint32_t, E_WS2>),
	/*0xE SRAM*/WriteHandler(GAMEPAK_Write<uint8_t, E_SRAM>,
							 GAMEPAK_Write<uint16_t, E_SRAM>,
							 GAMEPAK_Write<uint32_t, E_SRAM>),
	/*0xF SRAM_MIRROR*/WriteHandler(GAMEPAK_Write<uint8_t, E_SRAM>,
									GAMEPAK_Write<uint16_t, E_SRAM>,
									GAMEPAK_Write<uint32_t, E_SRAM>)
};
}
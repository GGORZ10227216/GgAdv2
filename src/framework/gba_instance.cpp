//
// Created by orzgg on 2020-09-04.
//

#include <gba_instance.h>
#include <bit_manipulate.h>
#include <io_enum.h>
#include "component/sub_module/dma/dma_enum.h"


namespace gg_core {
using namespace gg_io;

void IRQ_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  /* IF, IE, IME */
  const auto realRegAddr = relativeAddr & ~0x1;

  if (realRegAddr == OFFSET_IF) {
	// special behavior of IF
	for (int i = 0 ; i < 14 ; ++i) {
		if (TestBit(data, i)) {
		  ClearBit(instance.IF, i);
		} // if
	} // for
  } // if
  else {
	instance.mmu.IOReg[relativeAddr] = data;
  } // else
} // IF_Write()

void WAITCNT_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  if (relativeAddr == OFFSET_WAITCNT + 1) {
	data &= 0x7f; // Do not touch the GamePak type bit(bit 15).	GgAdv is a GBA emulator, not a GB/GBC emulator.
  } // if

  instance.mmu.IOReg[relativeAddr] = data;
  // Note: We do know that UpdateWaitState() will be called twice when relativeAddr is exactly 0x204.
  //       Because we are enforcing IOReg write in byte access.
  //       So the first write will update SRAM, WS0 and WS1 timing. Then the second write will update
  //       WS2.
  instance.mmu.UpdateWaitState();

  // FIXME: PHI Terminal Output?
  //        GamePak Prefetch Buffer?
} // WAITCNT_Write()

void HALTCNT_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  instance.mmu.IOReg[relativeAddr] = data;
  if (TestBit(data, 7)) {
	instance.systemStop = true;
  } // if
  else {
	instance.cpu.halt = true;
  } // else
} // HALTCNT_Write(

GbaInstance::GbaInstance(const std::filesystem::path& romPath) :
	mmu(*this, romPath),
	keypad(*this),
	timerController(*this),
	ppu(mmu.IOReg.data(),
		mmu.videoRAM.palette_data.data(),
		mmu.videoRAM.vram_data.data(),
		mmu.videoRAM.oam_data.data()
    ),
	dmaController(*this),
	apu(*this),
	cpu(*this),
	IF((uint16_t &) mmu.IOReg[gg_io::OFFSET_IF]),
	IE((uint16_t &) mmu.IOReg[gg_io::OFFSET_IE]),
	IME((uint16_t &) mmu.IOReg[gg_io::OFFSET_IME]),
	VCOUNT((uint16_t &) mmu.IOReg[OFFSET_VCOUNT]),
	DISPCNT((uint16_t &)mmu.IOReg[gg_io::OFFSET_DISPCNT]),
	DISPSTAT((uint16_t &)mmu.IOReg[gg_io::OFFSET_DISPSTAT])
//	timer(*this),
//	dmaController(*this)
{
  mmu.RegisterIOHandler({
    std::make_pair(OFFSET_IF, IRQ_Write),
	std::make_pair(OFFSET_IE, IRQ_Write),
	std::make_pair(OFFSET_IME, IRQ_Write),
	std::make_pair(OFFSET_WAITCNT, WAITCNT_Write),
	std::make_pair(OFFSET_HALTCNT, HALTCNT_Write)
  });

  timerController.BindWriteHandlerToMMU();
  dmaController.BindWriteHandlerToMMU();
  apu.BindWriteHandlerToMMU();
  _running = true;
} // GbaInstance()

void GbaInstance::StartMainLoop() {
  while (_running) {
	dmaController.IsActive() ? dmaController.Step() : cpu.Step();
  } // while
} // StartMainLoop()

void GbaInstance::NextFrame() {
  const uint64_t target = totalCycle + CYCLE_PER_FRAME;
  while (totalCycle < target) {
	dmaController.IsActive() ? dmaController.Step() : cpu.Step();
  } // while
} // EmulateUntil()

void GbaInstance::NormalState() {
  if (VCOUNT < 160) {
	// VCount is inside the range of visible screen.
	if (_cycleCounter < CYCLE_PER_VISIBLE_SCANLINE) {
	  // Since we are still remaining scanline level accuracy, so do not do anything
	  // before h-blank start.
	} // if
	else {
	  // H-Blank start
	  const bool hblankIrqRequestEnabled = gg_core::TestBit(DISPSTAT, E_FILED_DISPSTAT::H_BLANK_IRQ_BIT);
	  _cycleCounter -= CYCLE_PER_VISIBLE_SCANLINE;

	  if (hblankIrqRequestEnabled) {
		// System is currently allow to generate HBlank interrupt signal,
		// let's send this request to IF register.
		IF |= (1 << E_IRQ_HBLANK);
	  } // if

	  // Draw current scanline before entering h-blank.
	  ppu.DrawScreenLine();

	  systemState = E_SYSTEM_STATE::H_BLANK;
	  dmaController.NotifyChannel(E_DMA_TIMING::H_BLANK);
	  DISPSTAT |= (1 << E_FILED_DISPSTAT::H_BLANK_BIT);
	} // else
  } // if
  else {
	std::cerr << "Current VCount is out of range of visible screen but _ppuState is NORMAL, this should not happen!\n" << std::endl;
  } // else
} // NormalState()

void GbaInstance::CheckVCountSetting() {
  // TODO: Should we perform this check when PPU's constructor is called?
  //       (The VCount == 0 & VCount == VCount_Setting when system is just booted up)

  const uint8_t LYC = DISPSTAT >> 8;
  const bool lycMatched = LYC == VCOUNT;
  if (lycMatched) {
	DISPSTAT |= (1 << E_FILED_DISPSTAT::V_COUNTER_BIT);
	if (gg_core::TestBit(DISPSTAT, E_FILED_DISPSTAT::V_COUNTER_IRQ_BIT)) {
	  // System is currently allow to generate LYC match interrupt signal,
	  // let's send this request to IF register.
	  IF |= (1 << E_IRQ_VCOUNT);
	} // if
  } // if
  else {
	// v-counter != v-counter setting, clear v-counter flag.
	DISPSTAT &= ~(1 << E_FILED_DISPSTAT::V_COUNTER_BIT);
  } // else
} // CheckVCountSetting()

void GbaInstance::HBlankState() {
  // VCount is inside the range of visible screen.
  if (_cycleCounter < CYCLE_PER_HBLANK_INTERVAL) {
	// In H-Blank interval, do nothing.
  } // if
  else {
	// Advance to next scanline.
	_cycleCounter -= CYCLE_PER_HBLANK_INTERVAL;
	DISPSTAT &= ~(1 << E_FILED_DISPSTAT::H_BLANK_BIT);
	++VCOUNT;

	CheckVCountSetting();

	if (VCOUNT < LINE_PER_VISIBLE_SCREEN) {
	  systemState = E_SYSTEM_STATE::NORMAL;
	} // if
	else if (VCOUNT < LINE_PER_VISIBLE_SCREEN + LINE_PER_VBLANK_INTERVAL) {

	  systemState = E_SYSTEM_STATE::V_BLANK;
	  dmaController.NotifyChannel(E_DMA_TIMING::V_BLANK);
	  // According to GBATEK, v-blank flag only set when v-count inside the interval [160, 226]
	  // In other words, line 227 although is the last line of v-blank interval, but v-blank flag
	  // is not set.
	  if (VCOUNT != LINE_PER_VISIBLE_SCREEN + LINE_PER_VBLANK_INTERVAL - 1)
		DISPSTAT |= (1 << E_FILED_DISPSTAT::V_BLANK_BIT);

	  const bool vblankIrqRequestEnabled = gg_core::TestBit(DISPSTAT, E_FILED_DISPSTAT::V_BLANK_IRQ_BIT);
	  if (VCOUNT == LINE_PER_VISIBLE_SCREEN && vblankIrqRequestEnabled) {
		// System is currently allow to generate VBlank interrupt signal,
		// let's send this request to IF register.
		IF |= (1 << E_IRQ_VBLANK);
	  } // if
	} // else if
	else {
	  // current scanline is the last line of v-blank interval.
	  VCOUNT = 0;
	  systemState = E_SYSTEM_STATE::NORMAL;
	  DISPSTAT &= ~(1 << E_FILED_DISPSTAT::V_BLANK_BIT);
	} // else
  } // else
} // HBlankState()

void GbaInstance::VBlankState() {
  if (VCOUNT < 228) {
	// VCount is inside the range of v-blank interval.
	if (_cycleCounter < CYCLE_PER_VISIBLE_SCANLINE) {
	  // Since we are still remaining scanline level accuracy, so do not do anything
	  // before h-blank start.
	} // if
	else {
	  // H-Blank start
	  // Note that H-Blank here is fired within v-blank interval.
	  _cycleCounter -= CYCLE_PER_VISIBLE_SCANLINE;
	  // FIXME: Not sure to fire HBlank interrupt in v-blank interval.
	  const bool hblankIrqRequestEnabled = gg_core::TestBit(DISPSTAT, E_FILED_DISPSTAT::H_BLANK_IRQ_BIT);
	  if (hblankIrqRequestEnabled) {
		// System is currently allow to generate HBlank interrupt signal,
		// let's send this request to IF register.
		IF |= (1 << E_IRQ_HBLANK);
	  } // if

	  systemState = E_SYSTEM_STATE::H_BLANK;
	  DISPSTAT |= (1 << E_FILED_DISPSTAT::H_BLANK_BIT);
	} // else
  } // if
  else {
	std::cerr << "Current VCount is out of range of v-blank interval but _ppuState is VBLANK, this should not happen!\n" << std::endl;
  } // else
} // VBlankState()

void GbaInstance::Follow(const uint32_t deltaCycles) {
  _cycleCounter += deltaCycles;
  totalCycle += deltaCycles;
  timerController.Follow(deltaCycles);

  switch (systemState) {
	case E_SYSTEM_STATE::NORMAL:
	  NormalState();
	  break;
	case E_SYSTEM_STATE::H_BLANK:
	  HBlankState();
	  break;
	case E_SYSTEM_STATE::V_BLANK:
	  VBlankState();
	  break;
  } // switch
} // Follow()
}
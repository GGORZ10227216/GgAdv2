//
// Created by orzgg on 2021-12-20.
//

#include <dma/dma_controller.h>
#include <gba_instance.h>

namespace gg_core::gg_io {
dma::dma(GbaInstance &instance, int idx) :
	_irqId(static_cast<gg_cpu::IRQ_TYPE>(idx)),
	_srcAddr((uint32_t &) instance.mmu.IOReg[0xb0 + idx * 0xc]),
	_dstAddr((uint32_t &) instance.mmu.IOReg[0xb4 + idx * 0xc]),
	_cnt((uint16_t &) instance.mmu.IOReg[0xb8 + idx * 0xc]),
	_ctl((uint16_t &) instance.mmu.IOReg[0xba + idx * 0xc]),
	_instance(instance) {
  _internalCnt = 0;
  _internalSrc = 0;
  _internalDst = 0;
}

dma_controller::dma_controller(GbaInstance &instance) :
	_dmaChannels{dma(instance, 0), dma(instance, 1), dma(instance, 2), dma(instance, 3)},
	_instance(instance) {

}

void dma_controller::WriteControl(int idx, uint16_t value) {
  // TODO: fifo setting
  dma &tc = _dmaChannels[idx]; // target channel
  bool writeWhenEnable = TestBit(tc._ctl, ENABLE);

  /* timing logic */
  // TODO: Not sure if repeat bit and IMM timing are both set, what correct behavior is?
  ClearBit(_channelStatus[0], idx); // clear READY flag
  ClearBit(_channelStatus[1], idx); // clear H-BLANK flag
  ClearBit(_channelStatus[2], idx); // clear V-BLANK flag
  ClearBit(_channelStatus[3], idx); // clear SPECIAL flag

  if (!tc.IsEnabled()) {
	// Turned off by CPU
	// TODO: nba process some edge case here
  } // if
  else {
	tc._ctl = value;

	size_t stepIdxBase = (tc.ChunkSize() >> 2);
	tc._srcStep = tc._srcStepTable[stepIdxBase][tc.SrcAddrControl()];
	tc._dstStep = tc._dstStepTable[stepIdxBase][tc.DstAddrControl()];

	if (tc.SrcAddrControl() == RELOAD) {
//	  spdlog::error(
//		  fmt::format("Using prohibited srcAddrCnt code when accessing dma_{}",
//					  static_cast<int> (tc._irqId)
//		  ));

	  std::exit(-1);
	} // switch

	switch (tc.Timing()) {
	case HBLK:SetBit(_channelStatus[1], idx); // imm timing will set READY flag directly.
	  break;
	case VBLK:SetBit(_channelStatus[2], idx); // imm timing will set READY flag directly.
	  break;
	case SPECIAL:
	  if (tc._irqId == 3)
		SetBit(_channelStatus[3], idx); // imm timing will set READY flag directly.
	  break;
	}

	// TODO: schedule imm setting DMA here
	Trigger(_BV(idx)); // maybe I can use another way to do it?

	if (!writeWhenEnable) {
	  // turn DMA on when DMA off
	  // reload internal reg
	  tc.ResetInternalSrcAddr();
	  tc.ResetInternalDstAddr();
	  tc.ResetInternalCnt();

	  if (BitFieldValue<24, 4>(tc._srcAddr) == 0x8) {
		/// AGB manule says "When the Game Pak Bus has been set to the source address, make sure you select
		/// increment". But should we help programmer do that in emulator logic?
		tc._ctl &= 0b11 << 7;
	  } // if
	} // if
  } // else
} // dma_controller::WriteControl()

void dma_controller::Run() {
  while (_channelStatus[0]) {
	DoTransfer();
  } // while
}

void dma_controller::DoTransfer() {
  // todo: timing mechanism, fifo implement
  // Need at least one channel need to be set ACTIVATE.
  auto &tc = _dmaChannels[std::countr_zero(_channelStatus[0])];
  using namespace gg_mem;
  E_AccessType accessType = N_Cycle;

  while (tc._internalCnt > 0) {
	if (_dmaIsInterrupted) {
	  // nba do this, not sure this if is necessary
	  _dmaIsInterrupted = false;
	  return;
	} // if

	if (tc.ChunkSize() == 2) {
	  // halfword access
	  uint16_t readValue = tc._instance.mmu.Read<uint16_t>(tc._internalSrc, accessType);
	  tc._instance.mmu.Write<uint16_t>(tc._internalDst, readValue, accessType);
	} // if
	else {
	  // word access
	  uint32_t readValue = tc._instance.mmu.Read<uint32_t>(tc._internalSrc, accessType);
	  tc._instance.mmu.Write<uint32_t>(tc._internalDst, readValue, accessType);
	} // else

	tc._internalSrc += tc._srcStep;
	tc._internalDst += tc._dstStep;
	tc._internalCnt -= 1;

	accessType = S_Cycle;
  } // while

  ClearBit(_channelStatus[0], tc._irqId);

  if (tc.NeedIRQ()) {
	tc._instance.cpu.RaiseInterrupt(tc._irqId);
  } // if

  if (tc.NeedRepeat()) {
	uint16_t cntMask = (tc._irqId == gg_cpu::DMA_3) ? 0xffff : 0x3fff;
	if (tc._cnt != 0)
	  tc._internalCnt = tc._cnt & cntMask;
	else
	  tc._internalCnt = cntMask + 1;

	if (tc.DstAddrControl() == RELOAD)
	  tc._internalDst = tc._dstAddr;
  } // if
  else {
	ClearBit(tc._ctl, ENABLE);
	ClearBit(_channelStatus[1], tc._irqId); // clear H-BLANK flag
	ClearBit(_channelStatus[2], tc._irqId); // clear V-BLANK flag
	ClearBit(_channelStatus[3], tc._irqId); // clear SPECIAL flag
  } // else

//        ClearBit(_channelStatus, tc._irqId) ;
} // dma_controller::DoTransfer()

void dma_controller::Notify(DMA_TIMING requirement) {
  /// An interface to let framework notify dma controller to do h/v blank transfer
  switch (requirement) {
  case HBLK:Trigger(_channelStatus[1]);
	break;
  case VBLK:Trigger(_channelStatus[2]);
	break;
  case SPECIAL:Trigger(_channelStatus[3]);
	break;
	// TODO: fifo mechanism
  }
}

void dma_controller::Trigger(uint8_t flags) {
  int runningId = std::countr_zero(_channelStatus[0]);

  while (flags > 0) {
	int targetId = std::countr_zero(flags);

	auto &tc = _dmaChannels[targetId];
	_instance.runner.Schedule(2, [&](int) {
	  tc.twoCycleDelayedTrigger = nullptr;
	  if (targetId < runningId) {
		_dmaIsInterrupted = true;
	  } // else if

	  SetBit(_channelStatus[0], targetId);
	});

	ClearBit(flags, targetId);
  } // while()
} // dma_controller::Trigger()
}
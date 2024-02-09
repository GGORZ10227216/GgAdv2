//
// Created by Administrator on 10/31/2023.
//

#include "component/sub_module/dma/dma2.h"
#include <gba_instance.h>

namespace gg_core {
using namespace gg_io;
using namespace gg_mem;

void DMA_SAD_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned targetReg = relativeAddr & ~0x1;
  const unsigned offset = relativeAddr & 0x1;

  instance.mmu.IOReg[targetReg + offset] = data;
} // DMA_SAD_Write()

void DMA_DAD_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned targetReg = relativeAddr & ~0x1;
  const unsigned offset = relativeAddr & 0x1;
  uint8_t writeMask = 0xff;

  if (offset != 0) {
	if (targetReg == OFFSET_DMA3DAD_H)
	  writeMask = 0x0f;
	else if (targetReg > OFFSET_DMA3DAD_L)
	  writeMask = 0x07;
  } // if

  instance.mmu.IOReg[targetReg + offset] = data & writeMask;
} // DMA_DAD_Write()

void DMA_CNTL_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned targetReg = relativeAddr & ~0x1;
  const unsigned offset = relativeAddr & 0x1;
  uint8_t writeMask = 0xff;

  if (offset != 0) {
	writeMask = targetReg == OFFSET_DMA3CNT_L ? 0xff : 0x3f;
  } // if

  instance.mmu.IOReg[targetReg + offset] = data & writeMask;
} // DMA_CNTL_Write()

void DMA_CNTH_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned targetReg = relativeAddr & ~0x1;
  const unsigned offset = relativeAddr & 0x1;
  const unsigned channelIdx = (targetReg - OFFSET_DMA0CNT_H) / 12;

  uint8_t writeMask = offset == 0 ? ~0x1f : 0xff;
  instance.mmu.IOReg[targetReg + offset] = data & writeMask;

  // Note: Same as WAITCNT, DMA_CNTH_Write() will be called twice when relativeAddr is exactly OFFSET_DMAXCNT_H.
  instance.dmaController.ReloadChannelSetting(channelIdx);
} // DMA_CNTH_Write()

DMA::DMA(gg_core::GbaInstance &instance) :
  _instance(instance),
  _dmaChannels{ TransferChannel(instance, 0), TransferChannel(instance, 1),
				TransferChannel(instance, 2), TransferChannel(instance, 3) }
{
}

void DMA::BindWriteHandlerToMMU() {
  _instance.mmu.RegisterIOHandler({
	std::make_pair(OFFSET_DMA0SAD_L, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA0SAD_H, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA0DAD_L, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA0DAD_H, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA0CNT_L, DMA_CNTL_Write),
	std::make_pair(OFFSET_DMA0CNT_H, DMA_CNTH_Write),
	std::make_pair(OFFSET_DMA1SAD_L, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA1SAD_H, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA1DAD_L, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA1DAD_H, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA1CNT_L, DMA_CNTL_Write),
	std::make_pair(OFFSET_DMA1CNT_H, DMA_CNTH_Write),
	std::make_pair(OFFSET_DMA2SAD_L, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA2SAD_H, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA2DAD_L, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA2DAD_H, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA2CNT_L, DMA_CNTL_Write),
	std::make_pair(OFFSET_DMA2CNT_H, DMA_CNTH_Write),
	std::make_pair(OFFSET_DMA3SAD_L, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA3SAD_H, DMA_SAD_Write),
	std::make_pair(OFFSET_DMA3DAD_L, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA3DAD_H, DMA_DAD_Write),
	std::make_pair(OFFSET_DMA3CNT_L, DMA_CNTL_Write),
	std::make_pair(OFFSET_DMA3CNT_H, DMA_CNTH_Write)
  });
} // BindWriteHandlerToMMU()

void DMA::Step() {
  if (_runningChannelIdx == DMA_INACTIVE) {
	std::cerr << "DMA::Step() called when no DMA transfer is running." << std::endl;
	return;
  } // if


  auto &channel = _dmaChannels[_runningChannelIdx];
  channel.Transfer();

  if (!channel.activated) {
	auto isGamePakAddr = [](const unsigned addr) {
		return addr >= 0x0800'0000 && addr < 0x0e00'0000;
	};

	//  Internal time for DMA processing is 2I (normally), or 4I (if both source and destination are in gamepak memory area).
	if (!isGamePakAddr(channel.refSrcAddr.dword) || !isGamePakAddr(channel.refDstAddr.dword)) {
//	  elapsedCycle += 2;
	  _instance.Follow(2);
	} // if
	else {
//	  elapsedCycle += 4;
	  _instance.Follow(4);
	} // else

	// Resume another DMA transfer if possible. This case will happen when multiple DMA channels are notified at
	// the same time.
	// When the DMA channel which has the higher priority is done, the lower priority DMA transfer will be resumed.
	_runningChannelIdx = GetNextActivatedChannel();
  } // if

  return;
} // Step()

int DMA::GetNextActivatedChannel() {
  for (int i = 0 ; i < 4 ; ++i) {
	auto &channel = _dmaChannels[i];
	if (channel.activated) {
	  return i;
	} // if
  } // for

  return DMA_INACTIVE;
} // ResumeTransfer()

void DMA::GetChannelReady(const int idx) {
  _dmaChannels[idx].activated = true;

  if (_runningChannelIdx > idx) {
	_runningChannelIdx = idx;
  } // if
} // GetChannelReady()

void DMA::ReloadChannelSetting(const int idx) {
  TransferChannel &channel = _dmaChannels[idx];
  const auto oldCtl = channel._internalCtl;
  const auto currentCtl = channel.refCtl;

  const bool toggle = TestBit(oldCtl.word, 15) != TestBit(currentCtl.word, 15);
  const bool wasEnabled = TestBit(oldCtl.word, 15);

  // Need a mechanism to identify the system status(like VBlank, HBlank, etc.)
  // Possibly implement it in GbaInstance class.

  _dmaChannels[idx]._internalCtl = currentCtl;

  if (toggle && !wasEnabled) {
	// was disabled, but toggled --> turning on
	channel.Reset();

	if (channel.GetStartTiming() == E_DMA_TIMING::IMMEDIATE) {
	  // Start DMA transfer immediately.
	  NotifyChannel(E_DMA_TIMING::IMMEDIATE);
	} // if
  } // if
  else {
	// No toggle, just update channel setting.
  } // else
} // WriteChannelCtl()

void DMA::NotifyChannel(const gg_core::E_DMA_TIMING timing) {
  for (int i = 3 ; i >= 0 ; --i) {
	auto &ch = _dmaChannels[i];
	auto chStartTiming = ch.GetStartTiming();

	if (ch.IsEnabled()) {
	  const bool isASoundDMARequest = timing >= SPECIAL && chStartTiming == SPECIAL && (i == 1 || i == 2);
	  if (isASoundDMARequest) {
		if (timing == FIFO_A && ch._internalDstAddr.dword == 0x0400'00A0)
		  GetChannelReady(i);
		else if (timing == FIFO_B && ch._internalDstAddr.dword == 0x0400'00A4)
		  GetChannelReady(i);
	  } // if
	  else if (chStartTiming == timing) {
		GetChannelReady(i);
	  } // else if
	} // if
  } // for
} // NotifyChannel()
}
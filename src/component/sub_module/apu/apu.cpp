//
// Created by Administrator on 1/1/2024.
//
#include <apu.h>
#include <gba_instance.h>
#include <io_enum.h>

#include <iostream>

namespace gg_core {
using namespace gg_io;

void APU_SOUNDCNT_H_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  // TODO: Implement other fields
  const unsigned offset = relativeAddr & 0x1;

  if (offset == 1) {
	if (TestBit(data, 3))
	  instance.apu.dmaSoundChannels[0].ClearFifo();
	if (TestBit(data, 7))
	  instance.apu.dmaSoundChannels[1].ClearFifo();
  } // if
} // APU_SOUNDCNT_H_Write()

void APU::BindWriteHandlerToMMU() {
  _instance.mmu.RegisterIOHandler({
	std::make_pair(OFFSET_SOUNDCNT_H, APU_SOUNDCNT_H_Write)
  });
} // BindWriteHandlerToMMU()

void APU::PushFifo(const unsigned channelIdx, const uint32_t data) {
  // Normally, the FIFO length should be 4 * 32bit = 16byte.(according to fifo DMA's design)
  // But GBATEK says that the FIFO buffer can buffer 8 * 32bit(32byte) data.
  auto &dmaSoundChannel = dmaSoundChannels[channelIdx];

  if (dmaSoundChannel.CurrentPendingSampleCount() >= 32) {
//	std::cerr << "Warning: Push to full FIFO" << std::endl;
	return; // FIXME: Does dma sound channel just ignore the data when FIFO is full?
  } // if

  for (unsigned i = 0 ; i < 4 ; ++i) {
	dmaSoundChannel.fifoBuffer.push(data >> (i * 8));
  } // for
} // PushFifo()

uint8_t APU::PopFifo(const unsigned channelIdx) {
  auto &dmaSoundChannel = dmaSoundChannels[channelIdx];

  if (dmaSoundChannel.CurrentPendingSampleCount() == 0) {
//	std::cerr << "Warning: Pop from empty FIFO" << std::endl;
	return 0;
  } // if

  const uint8_t ret = dmaSoundChannel.fifoBuffer.front();
  dmaSoundChannel.fifoBuffer.pop();
  return ret;
} // PopFifo()

HOOKED_TIMER APU::GetHookedTimer(FIFO_NAME fifoName) {
  const auto HOOKED_TIMER_BIT = fifoName == FIFO_NAME::A ?
	  HOOKED_TIMER_FIFO_A_BIT : HOOKED_TIMER_FIFO_B_BIT;
  return static_cast<HOOKED_TIMER>(TestBit(SOUNDCNT_H, HOOKED_TIMER_BIT));
} // GetHookedTimer()

APU::APU(gg_core::GbaInstance &instance) :
	_instance(instance),
	SOUNDCNT_L((uint16_t &) instance.mmu.IOReg[OFFSET_SOUNDCNT_L]),
	SOUNDCNT_H((uint16_t &) instance.mmu.IOReg[OFFSET_SOUNDCNT_H])
{

}

void APU::OnTimerTimeout(const unsigned timerIdx) {
  for (unsigned i = 0 ; i < 2 ; ++i) {
	auto &dmaSoundChannel = dmaSoundChannels[i];
	const bool timerIsHookedOnChannel =
	  GetHookedTimer(static_cast<FIFO_NAME>(i)) == static_cast<HOOKED_TIMER>(timerIdx);
	if (timerIsHookedOnChannel) {
	  // FIXME: Just pop it out, because sound playback is not implemented yet.
	  PopFifo(i);

	  const bool dmaNeedsToBeTriggered = dmaSoundChannel.CurrentPendingSampleCount() <= 16;
	  if (dmaNeedsToBeTriggered) {
		const auto targetFifo = static_cast<E_DMA_TIMING>(i + E_DMA_TIMING::SPECIAL);
		_instance.dmaController.NotifyChannel(targetFifo);
	  } // if
	} // if
  } // for
} // OnTimerTimeout()
} // namespace gg_core
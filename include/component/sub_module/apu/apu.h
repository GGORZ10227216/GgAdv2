//
// Created by Administrator on 12/31/2023.
//

#ifndef GGADV_INCLUDE_COMPONENT_SUB_MODULE_APU_APU_H_
#define GGADV_INCLUDE_COMPONENT_SUB_MODULE_APU_APU_H_

#include <apu_enum.h>

#include <cstdint>
#include <queue>

namespace gg_core {
class ToneSweep {
  // AKA: Sound Channel 1
};

class Tone {
  // AKA: Sound Channel 2
};

class WaveOutput {
  // AKA: Sound Channel 3
};

class Noise {
  // AKA: Sound Channel 4
};

struct DMA_Sound {
  DMA_Sound() = default;

  // TODO: DMA_Sound should be able to be reset
  void Reset();
  unsigned CurrentPendingSampleCount() const { return fifoBuffer.size(); }
  void ClearFifo() {
	std::queue<uint8_t> empty;
	std::swap(fifoBuffer, empty);
  } // ClearFifo()

  std::queue<uint8_t> fifoBuffer;
  unsigned fifoIdx = 0;
};

class GbaInstance;

struct APU {
  APU() = delete;
  APU(GbaInstance &instance);

  void BindWriteHandlerToMMU();

  void OnTimerTimeout(const unsigned timerIdx);
  void PushFifo(const unsigned channelIdx, const uint32_t data);
  uint8_t PopFifo(const unsigned channelIdx);

  DMA_Sound dmaSoundChannels[2];
 private:
  HOOKED_TIMER GetHookedTimer(FIFO_NAME fifoName);

  GbaInstance &_instance;
  uint16_t &SOUNDCNT_L;
  uint16_t &SOUNDCNT_H;
  unsigned _idx;
};

} // namespace gg_core

#endif //GGADV_INCLUDE_COMPONENT_SUB_MODULE_APU_APU_H_

//
// Created by orzgg on 2021-12-20.
//

#include <array>
#include <bit>

#include <dma/dma.h>

#ifndef GGTHUMBTEST_DMA_CONTROLLER_H
#define GGTHUMBTEST_DMA_CONTROLLER_H

namespace gg_core {
class GbaInstance;

namespace gg_io {
class dma_controller {
public :
  dma_controller(GbaInstance &instance);

  void Run();

  void WriteControl(int idx, uint16_t value);

  void WriteSrc(int idx, uint32_t value) {
	uint32_t mask = idx == 0 ? 0x7ff'ffff : 0xfff'ffff;
	_dmaChannels[idx]._srcAddr = value & mask;
  } // WriteSrc()

  void WriteDsc(int idx, uint32_t value) {
	uint32_t mask = idx == 3 ? 0x7ff'ffff : 0xfff'ffff;
	_dmaChannels[idx]._dstAddr = value & mask;
  } // WriteDsc()

  void Notify(DMA_TIMING requirement);

private :
  std::array<dma, 4> _dmaChannels;
  uint8_t _channelStatus[4] = {0, 0, 0, 0};
  GbaInstance &_instance;
  bool _dmaIsInterrupted = false;

  void Trigger(uint8_t flags);
  void DoTransfer();
};
} // namespace gg_io
} // namespace gg_core

#endif //GGTHUMBTEST_DMA_CONTROLLER_H

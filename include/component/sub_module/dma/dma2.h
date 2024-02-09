//
// Created by Administrator on 10/25/2023.
//

#ifndef GGADV_INCLUDE_COMPONENT_SUB_MODULE_DMA2_H_
#define GGADV_INCLUDE_COMPONENT_SUB_MODULE_DMA2_H_

#include <cstdint>
#include "utility/bit_manipulate.h"
#include "dma_enum.h"
#include "component/memory/mem_enum.h"
#include "component/io/io_enum.h"

namespace gg_core {
class GbaInstance;

class TransferChannel {
 public:
  friend class DMA;
  TransferChannel(GbaInstance &instance, const unsigned idx);

  E_DST_ADDR_CTRL GetDstPostTransferBehavior();
  E_SRC_ADDR_CTRL GetSrcPostTransferBehavior();
  bool NeedRepeat();
  bool IsDwordTransfer();
  bool IsWordTransfer();
  E_DMA_TIMING GetStartTiming();
  bool NeedIRQ();
  bool IsEnabled();
  void Reset();
  void Disable();

  void Transfer();

  const gg_mem::io_reg32_t &refSrcAddr;
  const gg_mem::io_reg32_t &refDstAddr;
  const gg_mem::io_reg16_t &refCnt;
  gg_mem::io_reg16_t &refCtl;

  bool activated = false;
 private:
  void LoadCnt();
  void RequestIRQ();

  gg_core::GbaInstance &_instance;

  const unsigned _idx = 0;

  gg_mem::io_reg32_t _internalSrcAddr = 0;
  gg_mem::io_reg32_t _internalDstAddr = 0;
  gg_mem::io_reg16_t _internalCtl = 0;
  unsigned _internalCnt = 0, _internalCntReload = 0;
};

class DMA {
 public:
  DMA(gg_core::GbaInstance &instance);
  void BindWriteHandlerToMMU();

  void Step();
  void ReloadChannelSetting(const int idx);
  void NotifyChannel(const E_DMA_TIMING timing);
  void GetChannelReady(const int idx);
  [[nodiscard]] bool IsActive() const { return _runningChannelIdx != DMA_INACTIVE; }

 private:
  int GetNextActivatedChannel();

  GbaInstance &_instance;
  TransferChannel _dmaChannels[4];
  int _runningChannelIdx = DMA_INACTIVE;
};
}

#endif //GGADV_INCLUDE_COMPONENT_SUB_MODULE_DMA2_H_

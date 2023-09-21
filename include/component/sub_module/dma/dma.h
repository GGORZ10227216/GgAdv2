//
// Created by orzgg on 2021-12-20.
//

#include <cstdint>
#include <bit_manipulate.h>
#include <task.h>
#include <cpu_enum.h>

#ifndef GGTHUMBTEST_DMA_H
#define GGTHUMBTEST_DMA_H

namespace gg_core {
class GbaInstance;

namespace gg_io {
enum ADDR_BEHAVIOR { INC, DEC, FIX, RELOAD };
enum DMA_TIMING { IMM, VBLK, HBLK, SPECIAL };
enum CNT_BITNAME { ENABLE = 14 };

class dma {
public :
  friend class dma_controller;

  dma(GbaInstance &instance, int idx);

  void WriteControl(uint16_t value);
  void Run();

  ADDR_BEHAVIOR DstAddrControl() { return static_cast<ADDR_BEHAVIOR>(BitFieldValue<5, 2>(_ctl)); }
  ADDR_BEHAVIOR SrcAddrControl() { return static_cast<ADDR_BEHAVIOR>(BitFieldValue<7, 2>(_ctl)); }

  DMA_TIMING Timing() { return static_cast<DMA_TIMING>(BitFieldValue<12, 2>(_ctl)); }

  bool NeedRepeat() { return TestBit(_ctl, 9); }
  bool DRQ() { return TestBit(_ctl, 11); }
  bool IsEnabled() { return TestBit(_ctl, 15); }
  bool NeedIRQ() { return TestBit(_ctl, 14); }

  int ChunkSize() { return TestBit(_ctl, 10) ? 4 : 2; }

private :
  constexpr static std::array<std::array<int, 4>, 2> _srcStepTable{
	  std::array<int, 4>{2, -2, 0, 0},
	  std::array<int, 4>{4, -4, 0, 0}
  };

  constexpr static std::array<std::array<int, 4>, 2> _dstStepTable{
	  std::array<int, 4>{2, -2, 0, 0},
	  std::array<int, 4>{4, -4, 0, 4}
  };

  gg_cpu::IRQ_TYPE _irqId;

  uint32_t &_srcAddr;
  uint32_t &_dstAddr;

  int _srcStep, _dstStep;

  uint32_t _internalSrc, _internalDst, _internalCnt;

  uint16_t &_cnt;
  uint16_t &_ctl;

  Task *twoCycleDelayedTrigger = nullptr;

  GbaInstance &_instance;

  void ResetInternalSrcAddr() {
	int alignMask = ~(ChunkSize() - 1);
	_internalSrc = _srcAddr & alignMask;
  } // ResetInternalAddr()

  void ResetInternalDstAddr() {
	int alignMask = ~(ChunkSize() - 1);
	_internalDst = _dstAddr & alignMask;
  } // ResetInternalDstAddr()

  void ResetInternalCnt() {
	static uint16_t cntMask[] = {0x3fff, 0x3fff, 0x3fff, 0xffff};
	_internalCnt = _cnt & cntMask[_irqId];
	if (_cnt == 0)
	  _internalCnt = cntMask[_irqId] + 1;
  } // ResetInternalCnt()
};
}
}

#endif //GGTHUMBTEST_DMA_H

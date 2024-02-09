//
// Created by Administrator on 10/25/2023.
//

#include "component/sub_module/dma/dma2.h"
#include <gba_instance.h>

namespace gg_core {
using namespace gg_io;
using namespace gg_mem;

TransferChannel::TransferChannel(GbaInstance &instance, const unsigned idx) :
	_instance(instance),
	_idx(idx),
	refSrcAddr((io_reg32_t&)instance.mmu.IOReg[ OFFSET_DMA0SAD + idx * 0x0C ]),
	refDstAddr((io_reg32_t&)instance.mmu.IOReg[ OFFSET_DMA0DAD + idx * 0x0C ]),
	refCnt((io_reg16_t&)instance.mmu.IOReg[ OFFSET_DMA0CNT_L + idx * 0x0C ]),
	refCtl((io_reg16_t&)instance.mmu.IOReg[ OFFSET_DMA0CNT_H + idx * 0x0C ])
{

} // TransferChannel()

E_DST_ADDR_CTRL TransferChannel::GetDstPostTransferBehavior() {
  return static_cast<E_DST_ADDR_CTRL>(BitFieldValue<5, 2>(_internalCtl.word));
} // GetDstPostTransferBehavior()

E_SRC_ADDR_CTRL TransferChannel::GetSrcPostTransferBehavior() {
  return static_cast<E_SRC_ADDR_CTRL>(BitFieldValue<7, 2>(_internalCtl.word));
} // GetSrcPostTransferBehavior()

bool TransferChannel::NeedRepeat() {
  return TestBit(_internalCtl.word, 9);
} // NeedRepeat()

bool TransferChannel::IsDwordTransfer() {
  return TestBit(_internalCtl.word, 10);
} // IsDwordTransfer()

bool TransferChannel::IsWordTransfer() {
  return !IsDwordTransfer();
} // IsWordTransfer()

E_DMA_TIMING TransferChannel::GetStartTiming() {
  return static_cast<E_DMA_TIMING>(BitFieldValue<12, 2>(_internalCtl.word));
} // GetStartTiming()

bool TransferChannel::NeedIRQ() {
  return TestBit(_internalCtl.word, 14);
} // NeedIRQ()

bool TransferChannel::IsEnabled() {
  return TestBit(_internalCtl.word, E_DMA_CTLBIT::ENABLE_BIT);
} // IsEnabled()

void TransferChannel::Disable() {
  ClearBit(_internalCtl.word, E_DMA_CTLBIT::ENABLE_BIT);
  ClearBit(refCtl.word, E_DMA_CTLBIT::ENABLE_BIT);
} // Disable()

void TransferChannel::Reset() {
  const bool isFifoChannel = _idx == 1 || _idx == 2;
  const bool isGamePakChannel = _idx == 3;
  const uint32_t writeMask = IsDwordTransfer() ? ~0x3 : ~0x1;

  _internalSrcAddr = refSrcAddr.dword & writeMask;
  _internalDstAddr = refDstAddr.dword & writeMask;

  LoadCnt();

  if (GetStartTiming() >= SPECIAL) {
	switch (_idx) {
	  case 0:
		std::cerr << "Special start timing is not supported for DMA0" << std::endl;
		exit(-1);
		break;
	  case 1: case 2: {
		/* This channel is ready to acting as FIFO channel */
		uint16_t tmpCtl = _internalCtl.word;

		// Enforce dst_addr_ctrl to be [fixed].
		tmpCtl = tmpCtl & ~(0b11 << E_DMA_CTLBIT::DST_ADDR_CTRL_BIT);
		tmpCtl = tmpCtl | (0b10 << E_DMA_CTLBIT::DST_ADDR_CTRL_BIT);

		// Enforce channel in [repeat] mode.
		SetBit(tmpCtl, E_DMA_CTLBIT::REPEAT_BIT);

		// Enforce transfer type to [dword].
		SetBit(tmpCtl, E_DMA_CTLBIT::TRANSFER_TYPE_BIT);

		// Apply the ctl setting.
		_internalCtl.word = tmpCtl;

		// Enforce word count to [4] units.
		_internalCntReload = 4;
	  } break;
	  case 3:
		// TODO: Video capture mode
		break;
	} // switch
  } // if

  _internalCnt = _internalCntReload;
} // Reset()

void TransferChannel::LoadCnt() {
  if (refCnt.word == 0) {
	_internalCntReload = _idx == 3 ? 0x10000 : 0x4000;
  } // if
  else {
	_internalCntReload = refCnt.word;
  } // else
} // ResetCnt()

void TransferChannel::RequestIRQ() {
  if (NeedIRQ()) {
	_instance.IF |= (1 << (8 + _idx));
  } // if
} // RequestIRQ()

void TransferChannel::Transfer() {
  constexpr std::array<int, 4> addrStepDirectionTable{1, -1, 0, 1}; // INC, DEC, FIX, RELOAD
  auto memAccessTiming = _internalCnt == _internalCntReload ? gg_mem::N_Cycle : gg_mem::S_Cycle;

  // Perform DMA transfer for one DMA unit
  if (IsDwordTransfer()) {
	uint32_t srcValue = _instance.mmu.Read<uint32_t>(_internalSrcAddr.dword, memAccessTiming);
	_instance.mmu.Write<uint32_t>(_internalDstAddr.dword, srcValue, memAccessTiming);;

	// Update SAD/DAD
	_internalSrcAddr.dword += sizeof(DWORD) * addrStepDirectionTable[GetSrcPostTransferBehavior()];
	_internalDstAddr.dword += sizeof(DWORD) * addrStepDirectionTable[GetDstPostTransferBehavior()];
  } // if
  else {
	uint16_t srcValue = _instance.mmu.Read<uint16_t>(_internalSrcAddr.dword, memAccessTiming);
	_instance.mmu.Write<uint16_t>(_internalDstAddr.dword, srcValue, memAccessTiming);;

	// Update SAD/DAD
	_internalSrcAddr.dword += sizeof(WORD) * addrStepDirectionTable[GetSrcPostTransferBehavior()];
	_internalDstAddr.dword += sizeof(WORD) * addrStepDirectionTable[GetDstPostTransferBehavior()];
  }

  if (--_internalCnt == 0) {
	activated = false;

	RequestIRQ();

	if (NeedRepeat()) {
	  // Reload CNT_L if repeat is set
	  _internalCnt = _internalCntReload;

	  // Reload DAD if DstPostTransferBehavior is DST_RELOAD
	  if (GetDstPostTransferBehavior() == DST_RELOAD) {
		_internalDstAddr = refDstAddr;
	  } // if
	} // if
	else {
	  // Transfer finished and no need to repeat, clear enable bit immediately
	  Disable();
	} // else
  } // if

  return;
} // Step()
}
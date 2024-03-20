//
// Created by Orzgg on 12/27/2023.
//

#include <bit_manipulate.h>
#include <gba_instance.h>

namespace gg_core {
using namespace gg_io;

void TMXCNT_L_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned offset = relativeAddr & 0x1;
  const unsigned timerIdx = (relativeAddr - OFFSET_TM0CNT_L) / 4;
  instance.timerController.WriteReloadValue(timerIdx, data, offset);
} // TMXCNT_L_Write()

void TMXCNT_H_Write(GbaInstance &instance, uint32_t relativeAddr, uint8_t data) {
  const unsigned offset = relativeAddr & 0x1;
  uint8_t writeMask = 0xc7;

  if (offset == 0) {
	bool wasEnabled = TestBit(instance.mmu.IOReg[relativeAddr], 7);
	if (!wasEnabled && TestBit(data, 7)) {
	  // Timer is turning on
	  const unsigned timerIdx = (relativeAddr - OFFSET_TM0CNT_H) / 4;
//	  instance.Follow(2);
	  instance.timerController.ReloadTimer(timerIdx);
	} // if

	instance.mmu.IOReg[relativeAddr] = data & writeMask;
  } // if
  else {
	// High byte of TMXCNT is not writable
  } // if
} // TMXCTL_Write()

bool Timer::IsEnabled() const {
  return TestBit(cntH_Ref, 7);
} // IsEnabled()

bool Timer::NeedIRQ() const {
  return TestBit(cntH_Ref, 6);
} // NeedIRQ()

unsigned Timer::GetPrescaler() const {
  return prescalerTable[cntH_Ref & 0x3];
} // GetPrescaler()

Timer::E_WORKING_MODE Timer::GetWorkingMode() const {
  return TestBit(cntH_Ref, 2) ? CASCADE : CYCLE_COUNTING;
} // GetWorkingMode()

Timer::Timer(gg_core::GbaInstance &instance, const unsigned int idx) :
	instance(instance),
	idx(idx),
	cntL_Ref((uint16_t &) instance.mmu.IOReg[OFFSET_TM0CNT_L + idx * 4]),
	cntH_Ref((uint16_t &) instance.mmu.IOReg[OFFSET_TM0CNT_H + idx * 4])
{
} // Timer()

TimerController::TimerController(GbaInstance &instance) :
	_instance(instance)
{
} // TimerController()

void TimerController::BindWriteHandlerToMMU() {
  _instance.mmu.RegisterIOHandler({
	std::make_pair(OFFSET_TM0CNT_L, TMXCNT_L_Write),
	std::make_pair(OFFSET_TM1CNT_L, TMXCNT_L_Write),
	std::make_pair(OFFSET_TM2CNT_L, TMXCNT_L_Write),
	std::make_pair(OFFSET_TM3CNT_L, TMXCNT_L_Write),
	std::make_pair(OFFSET_TM0CNT_H, TMXCNT_H_Write),
	std::make_pair(OFFSET_TM1CNT_H, TMXCNT_H_Write),
	std::make_pair(OFFSET_TM2CNT_H, TMXCNT_H_Write),
	std::make_pair(OFFSET_TM3CNT_H, TMXCNT_H_Write)
  });
} // BindWriteHanderToMMU()

void TimerController::ReloadTimer(const unsigned int idx) {
  auto &timer = _timers[idx];
  timer.currentValue = timer.reloadValue;
  // Fixme: Should we reload pending value?
  timer.pending = 0;
} // ReloadTimer()

void TimerController::WriteReloadValue(const unsigned int idx, const uint16_t value, const unsigned int offset) {
  auto &timer = _timers[idx];
  uint8_t *cur = (uint8_t*)&timer.reloadValue;
  cur[offset] = value;
} // WriteReloadValue()

void TimerController::Follow(const unsigned int deltaCycles) {
  for (unsigned timerIdx = 0 ; timerIdx < 4 ; ++timerIdx) {
	auto &timer = _timers[timerIdx];
	if (timer.IsEnabled()) {
	  if (timerIdx == 0 || timer.mode == Timer::CYCLE_COUNTING) {
		timer.pending += deltaCycles;
		while (timer.pending >= timer.GetPrescaler()) {
		  timer.currentValue += timer.GetPrescaler();
		  timer.pending -= timer.GetPrescaler();
		} // while
	  } // if

	  if (timer.currentValue >= 0x10000) {
		const unsigned late = timer.currentValue - 0x10000;
		// Timer overflow
		if (timer.NeedIRQ()) {
		  SetBit(_instance.IF, timerIdx + gg_io::E_IRQ_TIMER0);
		} // if

		if (timerIdx != 3 && _timers[timerIdx + 1].GetWorkingMode() == Timer::CASCADE) {
		  // Cascade mode
		  ++_timers[timerIdx + 1].currentValue;
		} // if

		if (timerIdx == 0 || timerIdx == 1) {
		  // Timer 0/1 will notify apu to move sound data from FIFO to sound circuit
		  _instance.apu.OnTimerTimeout(timerIdx);
		} // if

		timer.currentValue = timer.reloadValue + late;
	  } // if

	  timer.cntL_Ref = timer.currentValue;
	} // if
  } // for
} // Follow()
} // namespace gg_core

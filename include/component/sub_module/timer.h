//
// Created by orzgg on 2021-11-25.
//

#include <array>
#include <cstdint>

#include <bit_manipulate.h>
#include <task.h>

#ifndef GGTHUMBTEST_TIMER_H
#define GGTHUMBTEST_TIMER_H

namespace gg_core::gg_io {
struct Timer {
  constexpr static std::array<int, 4> prescalerTb{1, 6, 8, 10};
  constexpr static int delayMask[4] = {0, 0x3F, 0xFF, 0x3FF};

  Timer(GbaInstance &instance, int idx);

  void ResetCounter() {
//            _Counter = _init + delayedClk;
	_internalCounter = _init;
  } // ResetCounter()

  int Prescaler() {
	return prescalerTb[_Control & 0b11];
  } // Prescaler()

  bool IsCascade() {
	return gg_core::TestBit(_Control, 2);
  } // IsCascade()

  bool NeedIRQ() {
	return gg_core::TestBit(_Control, 6);
  } // NeedIRQ()

  bool IsEnabled() {
	return gg_core::TestBit(_Control, 7);
  } // IsEnabled()

  void Stop() {
	_internalCounter += GetElapsedTimeFromLastStart();

  }

  uint16_t ReadCounter() {
	_internalCounter = GetElapsedTimeFromLastStart() >> Timer::prescalerTb[Prescaler()];
	_Counter = static_cast<uint16_t>(_internalCounter);
	return _Counter;
  } // ReadCounter()

  bool IsOverflow() {
	return _internalCounter >= _overflowValue;
  } // IsOverflow()

  uint64_t GetElapsedTimeFromLastStart();

  bool overflowed = false;

  uint16_t _init = 0;
  uint32_t _internalCounter = 0;
  const uint32_t _overflowValue = 0x1'0000;

  uint16_t &_Control;
  uint16_t &_Counter;
  uint64_t _startTimeStamp = 0;
  GbaInstance &_instance;

  std::function<void(int)> overflowAction;
  Task *scheduledTask = nullptr;
};
} // gg_core::gg_io

#endif //GGTHUMBTEST_TIMER_H

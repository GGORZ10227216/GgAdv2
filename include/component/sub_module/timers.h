//
// Created by orzgg on 2021-11-25.
//

#include <timer.h>
#include <cstdint>

#ifndef GGTHUMBTEST_TIMERS_H
#define GGTHUMBTEST_TIMERS_H

namespace gg_core {
class GbaInstance;

namespace gg_io {
struct Timers {
  Timers(GbaInstance &_mmu);

  void WriteControl(int idx, uint16_t value);

  uint16_t ReadCounter(int idx);
  void WriteCounter(int idx, uint16_t value) { timer[idx]._init = value; }
  void OnOverflow(int idx);
  void StartTimer(int idx, uint64_t delayed);
  void StopTimer(int idx);

  const uint32_t _overflowValue = 0x1'0000;

  Timer timer[4];
  GbaInstance &_instance;
};
} // namespace gg_io
} // namespace gg_core

#endif //GGTHUMBTEST_TIMERS_H

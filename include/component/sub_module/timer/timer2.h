//
// Created by Administrator on 12/27/2023.
//

#ifndef GGADV_INCLUDE_COMPONENT_SUB_MODULE_TIMER2_H_
#define GGADV_INCLUDE_COMPONENT_SUB_MODULE_TIMER2_H_
namespace gg_core {
struct Timer {
  enum E_WORKING_MODE { CYCLE_COUNTING, CASCADE };
  Timer(GbaInstance &instance, const unsigned idx);

  bool IsEnabled() const;
  bool NeedIRQ() const;
  E_WORKING_MODE GetWorkingMode() const;
  unsigned GetPrescaler() const;

  const unsigned idx = 0;
  E_WORKING_MODE mode = CYCLE_COUNTING;

  uint32_t currentValue = 0;

  uint32_t pending = 0;
  uint16_t reloadValue = 0;

  uint16_t &cntL_Ref;
  uint16_t &cntH_Ref;
  GbaInstance &instance;

  constexpr static std::array<unsigned, 4> prescalerTable = {
	  1, 64, 256, 1024
  };
};

struct TimerController {
 public:
  TimerController(GbaInstance &instance);
  void Follow(const unsigned deltaCycles);
  void ReloadTimer(const unsigned idx);
  void WriteReloadValue(const unsigned idx, const uint16_t value, const unsigned offset);

  void BindWriteHandlerToMMU();
 private:
  GbaInstance &_instance;
  std::array<Timer, 4> _timers{
	  Timer(_instance, 0),
	  Timer(_instance, 1),
	  Timer(_instance, 2),
	  Timer(_instance, 3)
  };
};
} // namespace gg_core


#endif //GGADV_INCLUDE_COMPONENT_SUB_MODULE_TIMER2_H_

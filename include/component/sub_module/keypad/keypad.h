//
// Created by Administrator on 1/7/2024.
//

#ifndef GGADV_INCLUDE_COMPONENT_SUB_MODULE_KEYPAD_KEYPAD_H_
#define GGADV_INCLUDE_COMPONENT_SUB_MODULE_KEYPAD_KEYPAD_H_

#include <cstdint>

namespace gg_core {
class GbaInstance;

struct Keypad {
  Keypad() = delete;
  Keypad(GbaInstance &instance);

 private:
  uint16_t &KEYINPUT;
  uint16_t &KEYCNT;
};

} // namespace gg_core



#endif //GGADV_INCLUDE_COMPONENT_SUB_MODULE_KEYPAD_KEYPAD_H_

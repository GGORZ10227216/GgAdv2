//
// Created by orzgg on 2020-09-04.
//


#include <gg_utility.h>
#include <bit_manipulate.h>

#include <cpu.h>
#include <mmu.h>
#include <ppu.h>
#include <apu.h>
#include <keypad/keypad.h>
#include "component/sub_module/dma/dma2.h"
#include "component/sub_module/timer/timer2.h"
#include <system_enum.h>
//#include <timers.h>
//#include <dma/dma_controller.h>


#ifndef GGADV_FRAMEWORK_BASE_H
#define GGADV_FRAMEWORK_BASE_H

namespace gg_core {
struct GbaInstance {
 private:
  bool _running = false;
  void NormalState();

  void HBlankState();
  void VBlankState();
  void CheckVCountSetting();

 public:
  GbaInstance(const std::filesystem::path& romPath);

  bool systemHalt = false;
  bool systemStop = false;

  uint64_t totalCycle = 0;
  unsigned _cycleCounter = 0;

  gg_mem::MMU mmu;
  uint16_t &IF;
  uint16_t &IE;
  uint16_t &IME;

  uint16_t &VCOUNT;
  uint16_t &DISPCNT;
  uint16_t &DISPSTAT;

  TimerController timerController;
  DMA dmaController;
  Keypad keypad;
  gg_gfx::PPU ppu;
  APU apu;

  gg_cpu::CPU cpu;

  unsigned _remainingScanlineForFrame = 0;

  E_SYSTEM_STATE systemState = E_SYSTEM_STATE::NORMAL;
  void StartMainLoop();
  void NextFrame();

  void Follow(const uint32_t deltaCycles);
};
}

#endif //GGADV_FRAMEWORK_BASE_H

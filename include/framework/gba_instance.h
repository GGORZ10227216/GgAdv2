//
// Created by orzgg on 2020-09-04.
//


#include <gg_utility.h>
#include <bit_manipulate.h>

#include <cpu.h>
#include <mmu.h>
#include <ppu.h>
//#include <timers.h>
//#include <dma/dma_controller.h>


#ifndef GGADV_FRAMEWORK_BASE_H
#define GGADV_FRAMEWORK_BASE_H

namespace gg_core {
struct GbaInstance {
  GbaInstance(const char *romPath);
  GbaInstance();
  unsigned cycleCounter;

  gg_mem::MMU mmu;
  gg_cpu::CPU cpu;
  gg_gfx::PPU ppu;

  uint16_t &IF;
  uint16_t &IE;
  uint16_t &IME;
//  gg_io::Timers timer;
//  gg_io::dma_controller dmaController;

  // Cycle accuracy is not the main goal of this project.
//  TaskRunner<64> runner;
};
}

#endif //GGADV_FRAMEWORK_BASE_H

//
// Created by buildmachine on 2021-03-17.
//


#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_OAM_HANDLER_H
#define GGTEST_OAM_HANDLER_H

namespace gg_core::gg_mem {
template<typename T>
auto OAM_Read(GbaInstance &instance, uint32_t absAddr) {
  const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_OAM_SIZE);
  VideoRAM &vram = instance.mmu.videoRAM;
  return reinterpret_cast<T &>(vram.oam_data[relativeAddr]);
} // IWRAM_Read()

template<typename T>
void OAM_Write(GbaInstance &instance, uint32_t absAddr, T data) {
  const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_OAM_SIZE);
  VideoRAM &vram = instance.mmu.videoRAM;

  if constexpr (sizeof(T) == 1) {
	// byte write to OAM is ignored
	return;
  } // if

  reinterpret_cast<T &>(vram.oam_data[relativeAddr]) = data;
} // IWRAM_Write()
}

#endif //GGTEST_OAM_HANDLER_H

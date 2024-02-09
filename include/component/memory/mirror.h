//
// Created by buildmachine on 2021-03-17.
//

#ifndef GGTEST_MIRROR_H
#define GGTEST_MIRROR_H

namespace gg_core::gg_mem {
inline uint32_t NORMAL_MIRROR(uint32_t absAddr, uint32_t regionSize) {
  return absAddr % regionSize;
}

inline uint32_t VRAM_MIRROR(uint32_t absAddr) {
  const uint32_t normalMirrorAddr = NORMAL_MIRROR(absAddr, 0x20000);
  if (normalMirrorAddr < E_VRAM_SIZE)
	return normalMirrorAddr;
  else
	return normalMirrorAddr - 0x8000;
}
}

#endif //GGTEST_MIRROR_H

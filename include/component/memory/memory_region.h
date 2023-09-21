//
// Created by orzgg on 2020-09-04.
//

#include <cstdint>

#include <component_class.h>
#include <mem_enum.h>

#ifndef GGADV_MEMORY_REGION_H
#define GGADV_MEMORY_REGION_H

namespace gg_core::gg_mem {
class MMU;

template<typename T>
struct Memory {
  template<E_AccessWidth W>
  uint8_t &Access(unsigned addr) {
	return static_cast<T *>(this)->AccessImpl<W>(addr);
  } // Access()

private :
  unsigned _ccRef;
  MemoryRegion() = delete;
  friend T;

//        template <E_RegionTag R, E_AccessWidth W>
//        inline unsigned _cycleCounting() {
//            return static_cast<T*>(this)->template _CycleCountingImpl<R, W>() ;
//        }
};
}

#endif //GGADV_MEMORY_REGION_H

//
// Created by orzgg on 2020-09-04.
//

#include <cstdint>

#include <component_class.h>
#include <mem_enum.h>

#ifndef GGADV_MEMORY_REGION_H
#define GGADV_MEMORY_REGION_H

namespace gg_core::gg_mem {
    class MMU ;
    template <typename T>
    struct MemoryRegion {
        MemoryRegion(unsigned& ccRef) : _ccRef(ccRef) {} // MemoryRegion()

        uint8_t &Access(unsigned addr, E_AccessWidth width) {
            return static_cast<T*>(this)->AccessImpl(addr, width) ;
        } // Access()

    private :
        unsigned& _ccRef ;
        MemoryRegion() = delete ;
        friend T ;
    };
}

#endif //GGADV_MEMORY_REGION_H

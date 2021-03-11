//
// Created by orzgg on 2020-09-04.
//
#include <array>
#include <cstdint>

#include <mem_enum.h>
#include <gba_bios.h>

#ifndef GGADV_GENERAL_MEMORY_H
#define GGADV_GENERAL_MEMORY_H

namespace gg_core::gg_mem {
    /**
         * Default WRAM Usage
         *     By default, the 256 bytes at 03007F00h-03007FFFh in Work RAM are reserved for
         *     Interrupt vector, Interrupt Stack, and BIOS Call Stack. The remaining WRAM is
         *     free for whatever use (including User Stack, which is initially located at 03007F00h).
         **/

    /**
     * GBA BIOS RAM Usage
     *      Below memory at 3007Fxxh is often accessed directly, or "via mirrors at 3FFFFxxh."
     *      3000000h 7F00h User Memory and User Stack              (sp_usr=3007F00h)
     *      3007F00h A0h   Default Interrupt Stack (6 words/time)  (sp_irq=3007FA0h)
     *      3007FA0h 40h   Default Supervisor Stack (4 words/time) (sp_svc=3007FE0h)
     *      3007FE0h 10h   Debug Exception Stack (4 words/time)    (sp_xxx=3007FF0h)
     *      3007FF0h 4     Pointer to Sound Buffer (for SWI Sound functions)
     *      3007FF4h 3     Reserved (unused)
     *      3007FF7h 1     Reserved (intro/nintendo logo related)
     *      3007FF8h 2     IRQ IF Check Flags (for SWI IntrWait/VBlankIntrWait functions)
     *      3007FFAh 1     Soft Reset Re-entry Flag (for SWI SoftReset function)
     *      3007FFBh 1     Reserved (intro/multiboot slave related)
     *      3007FFCh 4     Pointer to user IRQ handler (to 32bit ARM code)
     **/

    static inline unsigned BIOS_ACCESS_CYCLE() { return 1 ; }
    static inline unsigned IWRAM_ACCESS_CYCLE() { return 1 ; }
    static inline unsigned IO_ACCESS_CYCLE() { return 1 ; }

    template <typename W>
    static inline unsigned OWRAM_ACCESS_CYCLE() {
        if constexpr (SameSize<W, DWORD>())
            return 6 ;
        else
            return 3 ;
    } // OWRAM_ACCESS_CYCLE()
}

#endif //GGADV_GENERAL_MEMORY_H

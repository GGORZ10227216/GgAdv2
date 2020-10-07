#include <instruction/arm/api/v4_mem_api.h>

namespace gg_core::gg_cpu {
	static void swp(GbaInstance& instance) {
	    Swap<false>(instance) ;
	}

	static void swpb(GbaInstance& instance) {
        Swap<true>(instance) ;
	}
} // gg_core::gg_cpu

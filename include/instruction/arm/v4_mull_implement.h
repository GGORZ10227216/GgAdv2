#include <instruction/arm/api/v4_multiply_api.h>

namespace gg_core::gg_cpu {
	static void mull(GbaInstance& instance) {
	    MultiplyLong<false, false, false>(instance) ;
	}
	static void mulls(GbaInstance& instance) {
        MultiplyLong<false, false, true>(instance) ;
	}
	static void mlala(GbaInstance& instance) {
        MultiplyLong<false, true, false>(instance) ;
	}
	static void mlalas(GbaInstance& instance) {
        MultiplyLong<false, true, true>(instance) ;
	}
	static void mullu(GbaInstance& instance) {
        MultiplyLong<true, false, false>(instance) ;
	}
	static void mullus(GbaInstance& instance) {
        MultiplyLong<true, false, true>(instance) ;
	}
	static void mlalua(GbaInstance& instance) {
        MultiplyLong<true, true, false>(instance) ;
	}
	static void mlaluas(GbaInstance& instance) {
        MultiplyLong<true, true, true>(instance) ;
	}
} // gg_core::gg_cpu

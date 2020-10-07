#include <instruction/arm/api/v4_multiply_api.h>

namespace gg_core::gg_cpu {
	static void mul(GbaInstance& instance) {
	    Multiply<false, false>(instance) ;
	}
	static void muls(GbaInstance& instance) {
        Multiply<false, true>(instance) ;
	}

	static void mlaa(GbaInstance& instance) {
        Multiply<true, false>(instance) ;
	}

	static void mlaas(GbaInstance& instance) {
        Multiply<true, true>(instance) ;
	}
} // gg_core::gg_cpu

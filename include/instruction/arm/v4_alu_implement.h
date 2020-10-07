#include <bit_manipulate.h>
#include <instruction/arm/api/v4_alu_api.h>

namespace gg_core::gg_cpu {
	static void and_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void and_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void ands_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eor_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eors_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void sub_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sub_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsb_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void add_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adds_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adc_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbc_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsc_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void tsts_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void tsts_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmps_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmns_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void orr_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orr_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mov_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movs_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bic_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bics_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvn_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_ImmLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_RsLSL(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_ImmLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_RsLSR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_ImmASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_RsASR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_ImmROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvns_RsROR(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void andi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void andsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eori(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void eorsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void subi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void subsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsbsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void addi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void addsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adci(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void adcsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 + carry ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbci(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void sbcsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rsci(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void rscsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) - Rn + carry - 1 ;
			}, OP_TYPE::ARITHMETIC
		);
	}

	static void tstsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void teqsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) ^ op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmpsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) - op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void cmnsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) + op2 ;
			}, OP_TYPE::TEST
		);
	}

	static void orri(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void orrsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) | op2 ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void movsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bici(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void bicsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return static_cast<uint64_t>(Rn) & (~op2) ;
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvni(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

	static void mvnsi(GbaInstance& instance) {
		Alu_impl (instance,
			[](uint32_t Rn, uint32_t op2, bool carry) {
				return ~static_cast<uint64_t>(op2);
			}, OP_TYPE::LOGICAL
		);
	}

} // gg_core::gg_cpu

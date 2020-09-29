#include <bit_manipulate.h>
#include <v4_mem_api.h>

namespace gg_core::gg_cpu {
	static void strh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrlh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrlsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void strh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrlh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrlsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, false, false, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void struh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrulh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldruls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrulsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void struh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrulh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldruls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrulsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<false, true, false, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void strph_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrplh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrplsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void strpwh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpwlh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpwls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpwlsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void strph_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrplh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrplsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, false, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void strpwh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpwlh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpwls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpwlsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, false, true, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void strpuh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpulh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpuls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpulsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void strpuwh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, false, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpuwlh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, false, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpuwls_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, true, false, OFFSET_TYPE::RM>(instance) ;
	}

	static void ldrpuwlsh_Rm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, true, true, OFFSET_TYPE::RM>(instance) ;
	}

	static void strpuh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpulh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpuls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpulsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, false, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void strpuwh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, false, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpuwlh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, false, true, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpuwls_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, true, false, OFFSET_TYPE::IMM>(instance) ;
	}

	static void ldrpuwlsh_Imm(GbaInstance& instance) {
		HalfMemAccess_impl<true, true, true, true, true, true, OFFSET_TYPE::IMM>(instance) ;
	}

} // gg_core::gg_cpu

#include <bit_manipulate.h>
#include <v4_mem_api.h>

namespace gg_core::gg_cpu {
	static void str(GbaInstance& instance) {
		MemAccess_impl<false, false, false, false, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrl(GbaInstance& instance) {
		MemAccess_impl<false, false, false, false, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strw(GbaInstance& instance) {
		MemAccess_impl<false, false, false, false, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlw(GbaInstance& instance) {
		MemAccess_impl<false, false, false, false, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strb(GbaInstance& instance) {
		MemAccess_impl<false, false, false, true, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlb(GbaInstance& instance) {
		MemAccess_impl<false, false, false, true, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strbw(GbaInstance& instance) {
		MemAccess_impl<false, false, false, true, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlbw(GbaInstance& instance) {
		MemAccess_impl<false, false, false, true, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void stru(GbaInstance& instance) {
		MemAccess_impl<false, false, true, false, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlu(GbaInstance& instance) {
		MemAccess_impl<false, false, true, false, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void struw(GbaInstance& instance) {
		MemAccess_impl<false, false, true, false, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrluw(GbaInstance& instance) {
		MemAccess_impl<false, false, true, false, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strub(GbaInstance& instance) {
		MemAccess_impl<false, false, true, true, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlub(GbaInstance& instance) {
		MemAccess_impl<false, false, true, true, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strubw(GbaInstance& instance) {
		MemAccess_impl<false, false, true, true, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlubw(GbaInstance& instance) {
		MemAccess_impl<false, false, true, true, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strp(GbaInstance& instance) {
		MemAccess_impl<false, true, false, false, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlp(GbaInstance& instance) {
		MemAccess_impl<false, true, false, false, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpw(GbaInstance& instance) {
		MemAccess_impl<false, true, false, false, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpw(GbaInstance& instance) {
		MemAccess_impl<false, true, false, false, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpb(GbaInstance& instance) {
		MemAccess_impl<false, true, false, true, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpb(GbaInstance& instance) {
		MemAccess_impl<false, true, false, true, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpbw(GbaInstance& instance) {
		MemAccess_impl<false, true, false, true, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpbw(GbaInstance& instance) {
		MemAccess_impl<false, true, false, true, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpu(GbaInstance& instance) {
		MemAccess_impl<false, true, true, false, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpu(GbaInstance& instance) {
		MemAccess_impl<false, true, true, false, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpuw(GbaInstance& instance) {
		MemAccess_impl<false, true, true, false, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpuw(GbaInstance& instance) {
		MemAccess_impl<false, true, true, false, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpub(GbaInstance& instance) {
		MemAccess_impl<false, true, true, true, false, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpub(GbaInstance& instance) {
		MemAccess_impl<false, true, true, true, false, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void strpubw(GbaInstance& instance) {
		MemAccess_impl<false, true, true, true, true, false, SHIFT_TYPE::NONE>(instance) ;
	}

	static void ldrlpubw(GbaInstance& instance) {
		MemAccess_impl<false, true, true, true, true, true, SHIFT_TYPE::NONE>(instance) ;
	}

	static void stri_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void stri_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void stri_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void stri_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrli_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrli_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrli_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrli_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, false, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strbi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strbi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strbi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strbi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlbi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlbi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlbi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlbi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strbwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strbwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strbwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strbwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlbwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlbwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlbwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlbwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, false, true, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strui_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strui_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strui_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strui_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlui_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlui_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlui_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlui_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void struwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void struwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void struwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void struwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrluwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrluwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrluwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrluwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, false, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strubi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strubi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strubi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strubi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlubi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlubi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlubi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlubi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strubwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strubwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strubwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strubwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlubwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlubwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlubwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlubwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, false, true, true, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, false, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpbi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpbi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpbi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpbi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpbi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpbi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpbi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpbi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpbwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpbwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpbwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpbwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpbwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpbwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpbwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpbwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, false, true, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpui_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpui_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpui_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpui_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpui_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpui_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpui_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpui_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpuwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpuwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpuwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpuwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpuwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpuwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpuwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpuwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, false, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpubi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpubi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpubi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpubi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpubi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpubi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpubi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpubi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, false, true, SHIFT_TYPE::ROR>(instance) ;
	}

	static void strpubwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, false, SHIFT_TYPE::LSL>(instance) ;
	}

	static void strpubwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, false, SHIFT_TYPE::LSR>(instance) ;
	}

	static void strpubwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, false, SHIFT_TYPE::ASR>(instance) ;
	}

	static void strpubwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, false, SHIFT_TYPE::ROR>(instance) ;
	}

	static void ldrlpubwi_ImmLSL(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, true, SHIFT_TYPE::LSL>(instance) ;
	}

	static void ldrlpubwi_ImmLSR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, true, SHIFT_TYPE::LSR>(instance) ;
	}

	static void ldrlpubwi_ImmASR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, true, SHIFT_TYPE::ASR>(instance) ;
	}

	static void ldrlpubwi_ImmROR(GbaInstance& instance) {
		MemAccess_impl<true, true, true, true, true, true, SHIFT_TYPE::ROR>(instance) ;
	}

} // gg_core::gg_cpu

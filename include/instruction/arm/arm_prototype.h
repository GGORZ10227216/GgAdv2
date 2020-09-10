namespace gg_core {
	class GbaInstance;

	namespace gg_cpu {
		static void undefined(GbaInstance& instance) ;
		static void and_shtLSL(GbaInstance& instance) ;
		static void and_shtRsLSL(GbaInstance& instance) ;
		static void and_shtLSR(GbaInstance& instance) ;
		static void and_shtRsLSR(GbaInstance& instance) ;
		static void and_shtASR(GbaInstance& instance) ;
		static void and_shtRsASR(GbaInstance& instance) ;
		static void and_shtROR(GbaInstance& instance) ;
		static void and_shtRsROR(GbaInstance& instance) ;
		static void mul(GbaInstance& instance) ;
		static void strh_RmOffset(GbaInstance& instance) ;
		static void ands_shtLSL(GbaInstance& instance) ;
		static void ands_shtRsLSL(GbaInstance& instance) ;
		static void ands_shtLSR(GbaInstance& instance) ;
		static void ands_shtRsLSR(GbaInstance& instance) ;
		static void ands_shtASR(GbaInstance& instance) ;
		static void ands_shtRsASR(GbaInstance& instance) ;
		static void ands_shtROR(GbaInstance& instance) ;
		static void ands_shtRsROR(GbaInstance& instance) ;
		static void muls(GbaInstance& instance) ;
		static void ldrlh_RmOffset(GbaInstance& instance) ;
		static void ldrl(GbaInstance& instance) ;
		static void ldrlsh_RmOffset(GbaInstance& instance) ;
		static void eor_shtLSL(GbaInstance& instance) ;
		static void eor_shtRsLSL(GbaInstance& instance) ;
		static void eor_shtLSR(GbaInstance& instance) ;
		static void eor_shtRsLSR(GbaInstance& instance) ;
		static void eor_shtASR(GbaInstance& instance) ;
		static void eor_shtRsASR(GbaInstance& instance) ;
		static void eor_shtROR(GbaInstance& instance) ;
		static void eor_shtRsROR(GbaInstance& instance) ;
		static void mla(GbaInstance& instance) ;
		static void eors_shtLSL(GbaInstance& instance) ;
		static void eors_shtRsLSL(GbaInstance& instance) ;
		static void eors_shtLSR(GbaInstance& instance) ;
		static void eors_shtRsLSR(GbaInstance& instance) ;
		static void eors_shtASR(GbaInstance& instance) ;
		static void eors_shtRsASR(GbaInstance& instance) ;
		static void eors_shtROR(GbaInstance& instance) ;
		static void eors_shtRsROR(GbaInstance& instance) ;
		static void mlas(GbaInstance& instance) ;
		static void sub_shtLSL(GbaInstance& instance) ;
		static void sub_shtRsLSL(GbaInstance& instance) ;
		static void sub_shtLSR(GbaInstance& instance) ;
		static void sub_shtRsLSR(GbaInstance& instance) ;
		static void sub_shtASR(GbaInstance& instance) ;
		static void sub_shtRsASR(GbaInstance& instance) ;
		static void sub_shtROR(GbaInstance& instance) ;
		static void sub_shtRsROR(GbaInstance& instance) ;
		static void strh_immOffset(GbaInstance& instance) ;
		static void subs_shtLSL(GbaInstance& instance) ;
		static void subs_shtRsLSL(GbaInstance& instance) ;
		static void subs_shtLSR(GbaInstance& instance) ;
		static void subs_shtRsLSR(GbaInstance& instance) ;
		static void subs_shtASR(GbaInstance& instance) ;
		static void subs_shtRsASR(GbaInstance& instance) ;
		static void subs_shtROR(GbaInstance& instance) ;
		static void subs_shtRsROR(GbaInstance& instance) ;
		static void ldrlh_immOffset(GbaInstance& instance) ;
		static void ldrbl(GbaInstance& instance) ;
		static void ldrlsh_immOffset(GbaInstance& instance) ;
		static void rsb_shtLSL(GbaInstance& instance) ;
		static void rsb_shtRsLSL(GbaInstance& instance) ;
		static void rsb_shtLSR(GbaInstance& instance) ;
		static void rsb_shtRsLSR(GbaInstance& instance) ;
		static void rsb_shtASR(GbaInstance& instance) ;
		static void rsb_shtRsASR(GbaInstance& instance) ;
		static void rsb_shtROR(GbaInstance& instance) ;
		static void rsb_shtRsROR(GbaInstance& instance) ;
		static void rsbs_shtLSL(GbaInstance& instance) ;
		static void rsbs_shtRsLSL(GbaInstance& instance) ;
		static void rsbs_shtLSR(GbaInstance& instance) ;
		static void rsbs_shtRsLSR(GbaInstance& instance) ;
		static void rsbs_shtASR(GbaInstance& instance) ;
		static void rsbs_shtRsASR(GbaInstance& instance) ;
		static void rsbs_shtROR(GbaInstance& instance) ;
		static void rsbs_shtRsROR(GbaInstance& instance) ;
		static void add_shtLSL(GbaInstance& instance) ;
		static void add_shtRsLSL(GbaInstance& instance) ;
		static void add_shtLSR(GbaInstance& instance) ;
		static void add_shtRsLSR(GbaInstance& instance) ;
		static void add_shtASR(GbaInstance& instance) ;
		static void add_shtRsASR(GbaInstance& instance) ;
		static void add_shtROR(GbaInstance& instance) ;
		static void add_shtRsROR(GbaInstance& instance) ;
		static void umull(GbaInstance& instance) ;
		static void struh_RmOffset(GbaInstance& instance) ;
		static void adds_shtLSL(GbaInstance& instance) ;
		static void adds_shtRsLSL(GbaInstance& instance) ;
		static void adds_shtLSR(GbaInstance& instance) ;
		static void adds_shtRsLSR(GbaInstance& instance) ;
		static void adds_shtASR(GbaInstance& instance) ;
		static void adds_shtRsASR(GbaInstance& instance) ;
		static void adds_shtROR(GbaInstance& instance) ;
		static void adds_shtRsROR(GbaInstance& instance) ;
		static void umulls(GbaInstance& instance) ;
		static void ldrulh_RmOffset(GbaInstance& instance) ;
		static void ldrul(GbaInstance& instance) ;
		static void ldrulsh_RmOffset(GbaInstance& instance) ;
		static void adc_shtLSL(GbaInstance& instance) ;
		static void adc_shtRsLSL(GbaInstance& instance) ;
		static void adc_shtLSR(GbaInstance& instance) ;
		static void adc_shtRsLSR(GbaInstance& instance) ;
		static void adc_shtASR(GbaInstance& instance) ;
		static void adc_shtRsASR(GbaInstance& instance) ;
		static void adc_shtROR(GbaInstance& instance) ;
		static void adc_shtRsROR(GbaInstance& instance) ;
		static void umlal(GbaInstance& instance) ;
		static void adcs_shtLSL(GbaInstance& instance) ;
		static void adcs_shtRsLSL(GbaInstance& instance) ;
		static void adcs_shtLSR(GbaInstance& instance) ;
		static void adcs_shtRsLSR(GbaInstance& instance) ;
		static void adcs_shtASR(GbaInstance& instance) ;
		static void adcs_shtRsASR(GbaInstance& instance) ;
		static void adcs_shtROR(GbaInstance& instance) ;
		static void adcs_shtRsROR(GbaInstance& instance) ;
		static void umlals(GbaInstance& instance) ;
		static void sbc_shtLSL(GbaInstance& instance) ;
		static void sbc_shtRsLSL(GbaInstance& instance) ;
		static void sbc_shtLSR(GbaInstance& instance) ;
		static void sbc_shtRsLSR(GbaInstance& instance) ;
		static void sbc_shtASR(GbaInstance& instance) ;
		static void sbc_shtRsASR(GbaInstance& instance) ;
		static void sbc_shtROR(GbaInstance& instance) ;
		static void sbc_shtRsROR(GbaInstance& instance) ;
		static void smull(GbaInstance& instance) ;
		static void struh_immOffset(GbaInstance& instance) ;
		static void sbcs_shtLSL(GbaInstance& instance) ;
		static void sbcs_shtRsLSL(GbaInstance& instance) ;
		static void sbcs_shtLSR(GbaInstance& instance) ;
		static void sbcs_shtRsLSR(GbaInstance& instance) ;
		static void sbcs_shtASR(GbaInstance& instance) ;
		static void sbcs_shtRsASR(GbaInstance& instance) ;
		static void sbcs_shtROR(GbaInstance& instance) ;
		static void sbcs_shtRsROR(GbaInstance& instance) ;
		static void smulls(GbaInstance& instance) ;
		static void ldrulh_immOffset(GbaInstance& instance) ;
		static void ldrubl(GbaInstance& instance) ;
		static void ldrulsh_immOffset(GbaInstance& instance) ;
		static void rsc_shtLSL(GbaInstance& instance) ;
		static void rsc_shtRsLSL(GbaInstance& instance) ;
		static void rsc_shtLSR(GbaInstance& instance) ;
		static void rsc_shtRsLSR(GbaInstance& instance) ;
		static void rsc_shtASR(GbaInstance& instance) ;
		static void rsc_shtRsASR(GbaInstance& instance) ;
		static void rsc_shtROR(GbaInstance& instance) ;
		static void rsc_shtRsROR(GbaInstance& instance) ;
		static void smlal(GbaInstance& instance) ;
		static void rscs_shtLSL(GbaInstance& instance) ;
		static void rscs_shtRsLSL(GbaInstance& instance) ;
		static void rscs_shtLSR(GbaInstance& instance) ;
		static void rscs_shtRsLSR(GbaInstance& instance) ;
		static void rscs_shtASR(GbaInstance& instance) ;
		static void rscs_shtRsASR(GbaInstance& instance) ;
		static void rscs_shtROR(GbaInstance& instance) ;
		static void rscs_shtRsROR(GbaInstance& instance) ;
		static void smlals(GbaInstance& instance) ;
		static void mrs_CPSR(GbaInstance& instance) ;
		static void swp(GbaInstance& instance) ;
		static void strph_RmOffset(GbaInstance& instance) ;
		static void tsts_shtLSL(GbaInstance& instance) ;
		static void tsts_shtRsLSL(GbaInstance& instance) ;
		static void tsts_shtLSR(GbaInstance& instance) ;
		static void tsts_shtRsLSR(GbaInstance& instance) ;
		static void tsts_shtASR(GbaInstance& instance) ;
		static void tsts_shtRsASR(GbaInstance& instance) ;
		static void tsts_shtROR(GbaInstance& instance) ;
		static void tsts_shtRsROR(GbaInstance& instance) ;
		static void ldrplh_RmOffset(GbaInstance& instance) ;
		static void ldrpl(GbaInstance& instance) ;
		static void ldrplsh_RmOffset(GbaInstance& instance) ;
		static void msr_CPSR(GbaInstance& instance) ;
		static void bx(GbaInstance& instance) ;
		static void strpwh_RmOffset(GbaInstance& instance) ;
		static void teqs_shtLSL(GbaInstance& instance) ;
		static void teqs_shtRsLSL(GbaInstance& instance) ;
		static void teqs_shtLSR(GbaInstance& instance) ;
		static void teqs_shtRsLSR(GbaInstance& instance) ;
		static void teqs_shtASR(GbaInstance& instance) ;
		static void teqs_shtRsASR(GbaInstance& instance) ;
		static void teqs_shtROR(GbaInstance& instance) ;
		static void teqs_shtRsROR(GbaInstance& instance) ;
		static void ldrpwlh_RmOffset(GbaInstance& instance) ;
		static void ldrpwl(GbaInstance& instance) ;
		static void ldrpwlsh_RmOffset(GbaInstance& instance) ;
		static void mrs_SPSR(GbaInstance& instance) ;
		static void swpb(GbaInstance& instance) ;
		static void strph_immOffset(GbaInstance& instance) ;
		static void cmps_shtLSL(GbaInstance& instance) ;
		static void cmps_shtRsLSL(GbaInstance& instance) ;
		static void cmps_shtLSR(GbaInstance& instance) ;
		static void cmps_shtRsLSR(GbaInstance& instance) ;
		static void cmps_shtASR(GbaInstance& instance) ;
		static void cmps_shtRsASR(GbaInstance& instance) ;
		static void cmps_shtROR(GbaInstance& instance) ;
		static void cmps_shtRsROR(GbaInstance& instance) ;
		static void ldrplh_immOffset(GbaInstance& instance) ;
		static void ldrpbl(GbaInstance& instance) ;
		static void ldrplsh_immOffset(GbaInstance& instance) ;
		static void msr_SPSR(GbaInstance& instance) ;
		static void strpwh_immOffset(GbaInstance& instance) ;
		static void cmns_shtLSL(GbaInstance& instance) ;
		static void cmns_shtRsLSL(GbaInstance& instance) ;
		static void cmns_shtLSR(GbaInstance& instance) ;
		static void cmns_shtRsLSR(GbaInstance& instance) ;
		static void cmns_shtASR(GbaInstance& instance) ;
		static void cmns_shtRsASR(GbaInstance& instance) ;
		static void cmns_shtROR(GbaInstance& instance) ;
		static void cmns_shtRsROR(GbaInstance& instance) ;
		static void ldrpwlh_immOffset(GbaInstance& instance) ;
		static void ldrpbwl(GbaInstance& instance) ;
		static void ldrpwlsh_immOffset(GbaInstance& instance) ;
		static void orr_shtLSL(GbaInstance& instance) ;
		static void orr_shtRsLSL(GbaInstance& instance) ;
		static void orr_shtLSR(GbaInstance& instance) ;
		static void orr_shtRsLSR(GbaInstance& instance) ;
		static void orr_shtASR(GbaInstance& instance) ;
		static void orr_shtRsASR(GbaInstance& instance) ;
		static void orr_shtROR(GbaInstance& instance) ;
		static void orr_shtRsROR(GbaInstance& instance) ;
		static void strpuh_RmOffset(GbaInstance& instance) ;
		static void orrs_shtLSL(GbaInstance& instance) ;
		static void orrs_shtRsLSL(GbaInstance& instance) ;
		static void orrs_shtLSR(GbaInstance& instance) ;
		static void orrs_shtRsLSR(GbaInstance& instance) ;
		static void orrs_shtASR(GbaInstance& instance) ;
		static void orrs_shtRsASR(GbaInstance& instance) ;
		static void orrs_shtROR(GbaInstance& instance) ;
		static void orrs_shtRsROR(GbaInstance& instance) ;
		static void ldrpulh_RmOffset(GbaInstance& instance) ;
		static void ldrpul(GbaInstance& instance) ;
		static void ldrpulsh_RmOffset(GbaInstance& instance) ;
		static void mov_shtLSL(GbaInstance& instance) ;
		static void mov_shtRsLSL(GbaInstance& instance) ;
		static void mov_shtLSR(GbaInstance& instance) ;
		static void mov_shtRsLSR(GbaInstance& instance) ;
		static void mov_shtASR(GbaInstance& instance) ;
		static void mov_shtRsASR(GbaInstance& instance) ;
		static void mov_shtROR(GbaInstance& instance) ;
		static void mov_shtRsROR(GbaInstance& instance) ;
		static void strpuwh_RmOffset(GbaInstance& instance) ;
		static void movs_shtLSL(GbaInstance& instance) ;
		static void movs_shtRsLSL(GbaInstance& instance) ;
		static void movs_shtLSR(GbaInstance& instance) ;
		static void movs_shtRsLSR(GbaInstance& instance) ;
		static void movs_shtASR(GbaInstance& instance) ;
		static void movs_shtRsASR(GbaInstance& instance) ;
		static void movs_shtROR(GbaInstance& instance) ;
		static void movs_shtRsROR(GbaInstance& instance) ;
		static void ldrpuwlh_RmOffset(GbaInstance& instance) ;
		static void ldrpuwl(GbaInstance& instance) ;
		static void ldrpuwlsh_RmOffset(GbaInstance& instance) ;
		static void bic_shtLSL(GbaInstance& instance) ;
		static void bic_shtRsLSL(GbaInstance& instance) ;
		static void bic_shtLSR(GbaInstance& instance) ;
		static void bic_shtRsLSR(GbaInstance& instance) ;
		static void bic_shtASR(GbaInstance& instance) ;
		static void bic_shtRsASR(GbaInstance& instance) ;
		static void bic_shtROR(GbaInstance& instance) ;
		static void bic_shtRsROR(GbaInstance& instance) ;
		static void strpuh_immOffset(GbaInstance& instance) ;
		static void bics_shtLSL(GbaInstance& instance) ;
		static void bics_shtRsLSL(GbaInstance& instance) ;
		static void bics_shtLSR(GbaInstance& instance) ;
		static void bics_shtRsLSR(GbaInstance& instance) ;
		static void bics_shtASR(GbaInstance& instance) ;
		static void bics_shtRsASR(GbaInstance& instance) ;
		static void bics_shtROR(GbaInstance& instance) ;
		static void bics_shtRsROR(GbaInstance& instance) ;
		static void ldrpulh_immOffset(GbaInstance& instance) ;
		static void ldrpubl(GbaInstance& instance) ;
		static void ldrpulsh_immOffset(GbaInstance& instance) ;
		static void mvn_shtLSL(GbaInstance& instance) ;
		static void mvn_shtRsLSL(GbaInstance& instance) ;
		static void mvn_shtLSR(GbaInstance& instance) ;
		static void mvn_shtRsLSR(GbaInstance& instance) ;
		static void mvn_shtASR(GbaInstance& instance) ;
		static void mvn_shtRsASR(GbaInstance& instance) ;
		static void mvn_shtROR(GbaInstance& instance) ;
		static void mvn_shtRsROR(GbaInstance& instance) ;
		static void strpuwh_immOffset(GbaInstance& instance) ;
		static void mvns_shtLSL(GbaInstance& instance) ;
		static void mvns_shtRsLSL(GbaInstance& instance) ;
		static void mvns_shtLSR(GbaInstance& instance) ;
		static void mvns_shtRsLSR(GbaInstance& instance) ;
		static void mvns_shtASR(GbaInstance& instance) ;
		static void mvns_shtRsASR(GbaInstance& instance) ;
		static void mvns_shtROR(GbaInstance& instance) ;
		static void mvns_shtRsROR(GbaInstance& instance) ;
		static void ldrpuwlh_immOffset(GbaInstance& instance) ;
		static void ldrpubwl(GbaInstance& instance) ;
		static void ldrpuwlsh_immOffset(GbaInstance& instance) ;
		static void andi(GbaInstance& instance) ;
		static void andsi(GbaInstance& instance) ;
		static void eori(GbaInstance& instance) ;
		static void eorsi(GbaInstance& instance) ;
		static void subi(GbaInstance& instance) ;
		static void subsi(GbaInstance& instance) ;
		static void rsbi(GbaInstance& instance) ;
		static void rsbsi(GbaInstance& instance) ;
		static void addi(GbaInstance& instance) ;
		static void addsi(GbaInstance& instance) ;
		static void adci(GbaInstance& instance) ;
		static void adcsi(GbaInstance& instance) ;
		static void sbci(GbaInstance& instance) ;
		static void sbcsi(GbaInstance& instance) ;
		static void rsci(GbaInstance& instance) ;
		static void rscsi(GbaInstance& instance) ;
		static void tstsi(GbaInstance& instance) ;
		static void teqsi(GbaInstance& instance) ;
		static void cmpsi(GbaInstance& instance) ;
		static void cmnsi(GbaInstance& instance) ;
		static void orri(GbaInstance& instance) ;
		static void orrsi(GbaInstance& instance) ;
		static void movi(GbaInstance& instance) ;
		static void movsi(GbaInstance& instance) ;
		static void bici(GbaInstance& instance) ;
		static void bicsi(GbaInstance& instance) ;
		static void mvni(GbaInstance& instance) ;
		static void mvnsi(GbaInstance& instance) ;
		static void str(GbaInstance& instance) ;
		static void strw(GbaInstance& instance) ;
		static void ldrwl(GbaInstance& instance) ;
		static void strb(GbaInstance& instance) ;
		static void strbw(GbaInstance& instance) ;
		static void ldrbwl(GbaInstance& instance) ;
		static void stru(GbaInstance& instance) ;
		static void struw(GbaInstance& instance) ;
		static void ldruwl(GbaInstance& instance) ;
		static void strub(GbaInstance& instance) ;
		static void strubw(GbaInstance& instance) ;
		static void ldrubwl(GbaInstance& instance) ;
		static void strp(GbaInstance& instance) ;
		static void strpw(GbaInstance& instance) ;
		static void strpb(GbaInstance& instance) ;
		static void strpbw(GbaInstance& instance) ;
		static void strpu(GbaInstance& instance) ;
		static void strpuw(GbaInstance& instance) ;
		static void strpub(GbaInstance& instance) ;
		static void strpubw(GbaInstance& instance) ;
		static void stri(GbaInstance& instance) ;
		static void ldril(GbaInstance& instance) ;
		static void striw(GbaInstance& instance) ;
		static void ldriwl(GbaInstance& instance) ;
		static void strib(GbaInstance& instance) ;
		static void ldribl(GbaInstance& instance) ;
		static void stribw(GbaInstance& instance) ;
		static void ldribwl(GbaInstance& instance) ;
		static void striu(GbaInstance& instance) ;
		static void ldriul(GbaInstance& instance) ;
		static void striuw(GbaInstance& instance) ;
		static void ldriuwl(GbaInstance& instance) ;
		static void striub(GbaInstance& instance) ;
		static void ldriubl(GbaInstance& instance) ;
		static void striubw(GbaInstance& instance) ;
		static void ldriubwl(GbaInstance& instance) ;
		static void strip(GbaInstance& instance) ;
		static void ldripl(GbaInstance& instance) ;
		static void stripw(GbaInstance& instance) ;
		static void ldripwl(GbaInstance& instance) ;
		static void stripb(GbaInstance& instance) ;
		static void ldripbl(GbaInstance& instance) ;
		static void stripbw(GbaInstance& instance) ;
		static void ldripbwl(GbaInstance& instance) ;
		static void stripu(GbaInstance& instance) ;
		static void ldripul(GbaInstance& instance) ;
		static void stripuw(GbaInstance& instance) ;
		static void ldripuwl(GbaInstance& instance) ;
		static void stripub(GbaInstance& instance) ;
		static void ldripubl(GbaInstance& instance) ;
		static void stripubw(GbaInstance& instance) ;
		static void ldripubwl(GbaInstance& instance) ;
		static void stm(GbaInstance& instance) ;
		static void ldml(GbaInstance& instance) ;
		static void stmw(GbaInstance& instance) ;
		static void ldmwl(GbaInstance& instance) ;
		static void stms(GbaInstance& instance) ;
		static void ldmsl(GbaInstance& instance) ;
		static void stmsw(GbaInstance& instance) ;
		static void ldmswl(GbaInstance& instance) ;
		static void stmu(GbaInstance& instance) ;
		static void ldmul(GbaInstance& instance) ;
		static void stmuw(GbaInstance& instance) ;
		static void ldmuwl(GbaInstance& instance) ;
		static void stmus(GbaInstance& instance) ;
		static void ldmusl(GbaInstance& instance) ;
		static void stmusw(GbaInstance& instance) ;
		static void ldmuswl(GbaInstance& instance) ;
		static void stmp(GbaInstance& instance) ;
		static void ldmpl(GbaInstance& instance) ;
		static void stmpw(GbaInstance& instance) ;
		static void ldmpwl(GbaInstance& instance) ;
		static void stmps(GbaInstance& instance) ;
		static void ldmpsl(GbaInstance& instance) ;
		static void stmpsw(GbaInstance& instance) ;
		static void ldmpswl(GbaInstance& instance) ;
		static void stmpu(GbaInstance& instance) ;
		static void ldmpul(GbaInstance& instance) ;
		static void stmpuw(GbaInstance& instance) ;
		static void ldmpuwl(GbaInstance& instance) ;
		static void stmpus(GbaInstance& instance) ;
		static void ldmpusl(GbaInstance& instance) ;
		static void stmpusw(GbaInstance& instance) ;
		static void ldmpuswl(GbaInstance& instance) ;
		static void b(GbaInstance& instance) ;
		static void bl(GbaInstance& instance) ;
		static void svc(GbaInstance& instance) ;
		static void undefined(GbaInstance& instance) ;
	} // gg_cpu
} // gg_core

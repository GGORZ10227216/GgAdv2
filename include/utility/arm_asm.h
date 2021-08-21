//
// Created by orzgg on 2021-08-17.
//

#include <fmt/format.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#ifndef GGTEST_ARM_ASM_H
#define GGTEST_ARM_ASM_H

enum class ASMMODE {ARM, THUMB} ;

class ArmAssembler {
public :
    ArmAssembler(ASMMODE mode = ASMMODE::ARM) {
        ksMode = mode == ASMMODE::ARM ? KS_MODE_ARM : KS_MODE_THUMB ;
        csMode = mode == ASMMODE::ARM ? CS_MODE_ARM : CS_MODE_THUMB ;

        err = ks_open(KS_ARCH_ARM, ksMode, &ks);

        if (err != KS_ERR_OK) {
            printf("ERROR: failed on ks_open(), quit\n");
            exit(-1);
        }

        if (cs_open(CS_ARCH_ARM, csMode, &handle) != CS_ERR_OK)
            exit(-1);
    }

    uint32_t ASM(std::string CODE) {
        if (ks_asm(ks, CODE.c_str(), 0, &encode, &size, &count_asm) != KS_ERR_OK) {
            printf("[%s] ERROR: ks_asm() failed & count_asm = %lu, error = %u\n",
                   CODE.c_str(), count_asm, ks_errno(ks));
            return 0xffffffff;
        } else {
            uint32_t result = *reinterpret_cast<uint32_t *>(encode);
            ks_free(encode);
            return result;
        }
    }

    std::string DASM(uint32_t binary) {
        count_dasm = cs_disasm(handle, reinterpret_cast<uint8_t *>(&binary), 4, 0x0, 0, &insn);
        if (count_dasm > 0) {
            std::string result = fmt::format("{} {}", insn[0].mnemonic, insn[0].op_str);
            cs_free(insn, count_dasm);
            return result;
        } // if
        else {
            return "Disassemble failed.";
        } // else
    }

    ~ArmAssembler() {
        ks_close(ks);
        cs_close(&handle);
    }

private:
    ks_engine *ks;
    ks_err err;
    size_t count_asm;
    unsigned char *encode;
    size_t size;

    csh handle;
    cs_insn *insn;
    size_t count_dasm;

    ks_mode ksMode ;
    cs_mode csMode ;
};

#endif //GGTEST_ARM_ASM_H

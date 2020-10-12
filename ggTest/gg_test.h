//
// Created by jason4_lee on 2020-10-12.
//
#include <string>
#include <array>
#include <optional>

#include <cstdlib>

#include <gtest/gtest.h>
#include <fmt/format.h>
#include <keystone/keystone.h>

#include <framework/gba_instance.h>
#include <arm/arm.h>

#ifndef GGTEST_GG_TEST_H
#define GGTEST_GG_TEST_H

class ggTest : public testing::Test {
protected:
    enum E_RegName {
        r0, r1, r2, r3, r4, r5,
        r6, r7, r8, r9, r10, r11,
        r12, r13, r14, r15
    };

    enum E_Shift {
        lsl, lsr, asr, ror
    };

    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;

    void SetUp() override {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM, &ks);
        if (err != KS_ERR_OK) {
            printf("ERROR: failed on ks_open(), quit\n");
            exit(-1);
        }
    } // SetUp()

    uint32_t ASM(std::string CODE) {
        if (ks_asm(ks, CODE.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
            printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                   count, ks_errno(ks));
        } else {
            uint32_t result = *reinterpret_cast<uint32_t *>(encode);
            ks_free(encode);
            return result;
        }
    }

    constexpr uint hashArm(u32 instr)
    {
        return ((instr >> 16) & 0xFF0) | ((instr >> 4) & 0xF);
    }

    void CheckStatus(const gg_core::GbaInstance& mine, const Arm& egg) const {
        for (int i = r0 ; i <= r15 ; ++i) {
            ASSERT_EQ(mine._status._regs[i], egg.regs[i]) << i ;
        }


        ASSERT_EQ(mine._status._cpsr, egg.cpsr) ;
    }

    void TearDown() override {
        ks_close(ks);
    } // TearDown()
};

static constexpr std::array<const char *, 16> regNames{
        "r0", "r1", "r2", "r3", "r4", "r5",
        "r6", "r7", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15"
};

static constexpr std::array<const char *, 4> shiftNames{
        "lsl", "lsr", "asr", "ror"
};

#endif //GGTEST_GG_TEST_H

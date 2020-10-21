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

class ArmAssembler {
public :
    ArmAssembler() {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM, &ks);
        if (err != KS_ERR_OK) {
            printf("ERROR: failed on ks_open(), quit\n");
            exit(-1);
        }
    }

    uint32_t ASM(std::string CODE) {
        if (ks_asm(ks, CODE.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
            printf("[%s] ERROR: ks_asm() failed & count = %lu, error = %u\n",
                   CODE.c_str(), count, ks_errno(ks));
        } else {
            uint32_t result = *reinterpret_cast<uint32_t *>(encode);
            ks_free(encode);
            return result;
        }
    }

    ~ArmAssembler() {
        ks_close(ks);
    }

private:
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
};

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

    constexpr uint hashArm(u32 instr)
    {
        return ((instr >> 16) & 0xFF0) | ((instr >> 4) & 0xF);
    }

    void CheckStatus(const gg_core::GbaInstance& mine, const Arm& egg, const std::string inst, const std::string testcase) const {
        for (int i = r0 ; i <= r15 ; ++i) {
            ASSERT_EQ(mine._status._regs[i], egg.regs[i]) << inst << '\n' << testcase << '\n' << PrintStatus(mine, egg) ;
        }


        ASSERT_EQ(mine._status.ReadCPSR(), egg.cpsr) << inst << '\n' << testcase << '\n' << PrintStatus(mine, egg) ;
    }

    std::string PrintStatus(const gg_core::GbaInstance& mine, const Arm& egg) const {
        std::stringstream ss ;
        for (int i = r0 ; i <= r15 ; ++i) {
            if (mine._status._regs[i] != egg.regs[i])
                ss << fmt::format("R{}=Mine:{:x},egg:{:x}",
                                     i, mine._status._regs[i], egg.regs[i]) << std::endl;

        } // for

        ss << fmt::format("cpsr_mine:{:x} cpsr_egg:{:x}", mine._status.ReadCPSR(), egg.cpsr)
                  << std::endl;
        return ss.str() ;
    }
};

using TestCase = std::array<uint32_t, 3>;
static constexpr std::array<TestCase, 74> TestCases{
        TestCase{0xffffffff, 0, 31},
        TestCase{0xffffffff, 0, 15},
        TestCase{0xffffffff, 0, 0},
        TestCase{0, 0xffffffff, 31},
        TestCase{0, 0xffffffff, 15},
        TestCase{0, 0xffffffff, 0},
        TestCase{0xffffffff, 0xffffffff, 31},
        TestCase{0xffffffff, 0xffffffff, 15},
        TestCase{0xffffffff, 0xffffffff, 0},
        TestCase{0, 0xdeadbeef, 0},
        TestCase{0, 0xdeadbeef, 1},
        TestCase{0, 0xdeadbeef, 2},
        TestCase{0, 0xdeadbeef, 3},
        TestCase{0, 0xdeadbeef, 4},
        TestCase{0, 0xdeadbeef, 5},
        TestCase{0, 0xdeadbeef, 6},
        TestCase{0, 0xdeadbeef, 7},
        TestCase{0, 0xdeadbeef, 8},
        TestCase{0, 0xdeadbeef, 9},
        TestCase{0, 0xdeadbeef, 10},
        TestCase{0, 0xdeadbeef, 11},
        TestCase{0, 0xdeadbeef, 12},
        TestCase{0, 0xdeadbeef, 13},
        TestCase{0, 0xdeadbeef, 14},
        TestCase{0, 0xdeadbeef, 15},
        TestCase{0, 0xdeadbeef, 16},
        TestCase{0, 0xdeadbeef, 17},
        TestCase{0, 0xdeadbeef, 18},
        TestCase{0, 0xdeadbeef, 19},
        TestCase{0, 0xdeadbeef, 20},
        TestCase{0, 0xdeadbeef, 21},
        TestCase{0, 0xdeadbeef, 22},
        TestCase{0, 0xdeadbeef, 23},
        TestCase{0, 0xdeadbeef, 24},
        TestCase{0, 0xdeadbeef, 25},
        TestCase{0, 0xdeadbeef, 26},
        TestCase{0, 0xdeadbeef, 27},
        TestCase{0, 0xdeadbeef, 28},
        TestCase{0, 0xdeadbeef, 29},
        TestCase{0, 0xdeadbeef, 30},
        TestCase{0, 0xdeadbeef, 31},
        TestCase{0, 0x55555555, 0},
        TestCase{0, 0x55555555, 1},
        TestCase{0, 0x55555555, 2},
        TestCase{0, 0x55555555, 3},
        TestCase{0, 0x55555555, 4},
        TestCase{0, 0x55555555, 5},
        TestCase{0, 0x55555555, 6},
        TestCase{0, 0x55555555, 7},
        TestCase{0, 0x55555555, 8},
        TestCase{0, 0x55555555, 9},
        TestCase{0, 0x55555555, 10},
        TestCase{0, 0x55555555, 11},
        TestCase{0, 0x55555555, 12},
        TestCase{0, 0x55555555, 13},
        TestCase{0, 0x55555555, 14},
        TestCase{0, 0x55555555, 15},
        TestCase{0, 0x55555555, 16},
        TestCase{0, 0x55555555, 17},
        TestCase{0, 0x55555555, 18},
        TestCase{0, 0x55555555, 19},
        TestCase{0, 0x55555555, 20},
        TestCase{0, 0x55555555, 21},
        TestCase{0, 0x55555555, 22},
        TestCase{0, 0x55555555, 23},
        TestCase{0, 0x55555555, 24},
        TestCase{0, 0x55555555, 25},
        TestCase{0, 0x55555555, 26},
        TestCase{0, 0x55555555, 27},
        TestCase{0, 0x55555555, 28},
        TestCase{0, 0x55555555, 29},
        TestCase{0, 0x55555555, 30},
        TestCase{0, 0x55555555, 31},
        TestCase{0, 0x55555555, 64}
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

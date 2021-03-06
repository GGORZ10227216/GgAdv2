//
// Created by jason4_lee on 2020-10-12.
//


#include <thread>
#include <future>
#include <utility>
#include <string>
#include <array>
#include <optional>
#include <cstdlib>

#include <gtest/gtest.h>
#include <fmt/format.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <gba_instance.h>
#include <core/core.h>
#include <gg_utility.h>
#include <cpu_enum.h>
#include <loop_tool.h>
#include <core/core.h>

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

        if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
            exit(-1);
    }

    uint32_t ASM(std::string CODE) {
        if (ks_asm(ks, CODE.c_str(), 0, &encode, &size, &count_asm) != KS_ERR_OK) {
            printf("[%s] ERROR: ks_asm() failed & count_asm = %lu, error = %u\n",
                   CODE.c_str(), count_asm, ks_errno(ks));
            return 0xffffffff ;
        } else {
            uint32_t result = *reinterpret_cast<uint32_t *>(encode);
            ks_free(encode);
            return result;
        }
    }

    std::string DASM(uint32_t binary) {
        count_dasm = cs_disasm(handle, reinterpret_cast<uint8_t*>(&binary), 4, 0x0, 0, &insn);
        if (count_dasm > 0) {
            std::string result = fmt::format("{} {}", insn[0].mnemonic, insn[0].op_str) ;
            cs_free(insn, count_dasm);
            return result ;
        } // if
        else {
            return "Disassemble failed." ;
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
    size_t count_dasm ;
};

class ggTest : public testing::Test {
protected:
    Arm& egg = arm;
    gg_core::GbaInstance gbaInstance ;
    gg_core::gg_mem::MMU& gg_mmu;
    gg_core::gg_cpu::CPU& instance;
    constexpr static char* testRomPath = "./testRom.gba" ;

    ArmAssembler gg_asm;

    ggTest():
        gbaInstance(testRomPath),
        gg_mmu(gbaInstance.mmu),
        instance(gbaInstance.cpu)
    {

    }

    constexpr uint hashArm(u32 instr)
    {
        return ((instr >> 16) & 0xFF0) | ((instr >> 4) & 0xF);
    }

    uint32_t CheckStatus(const gg_core::gg_cpu::CPU& mine, const Arm& egg) const {
        using namespace gg_core::gg_cpu ;

        uint32_t status_flag = 0 ;
        for (int i = r0 ; i <= pc ; ++i) {
            if (mine._regs[i] != egg.regs[i])
                status_flag |= gg_core::_BV(i) ;
        } // for

        if (mine.ReadCPSR() != egg.cpsr)
            status_flag |= gg_core::_BV(16) ;

        if (egg.pipe[0] != mine.fetchedBuffer[ !mine.fetchIdx ])
            status_flag |= gg_core::_BV(17) ;
        if (egg.pipe[1] != mine.fetchedBuffer[ mine.fetchIdx ])
            status_flag |= gg_core::_BV(18) ;

        return status_flag ;
    }

    std::string Diagnose(const gg_core::gg_cpu::CPU& mine, const Arm& egg, uint32_t status_flag) const {
        using namespace gg_core::gg_cpu ;

        std::string result ;
        for (int i = r0 ; i <= 18 ; ++i) {
            if (status_flag & gg_core::_BV(i)) {
                if (i < 16)
                    result += fmt::format("\t[X] r{}: mine={:x} ref={:x}\n", i, mine._regs[i], egg.regs[i]) ;
                else if ( i == 16 )
                    result += fmt::format("\t[X] cpsr: mine={:x} ref={:x}\n", mine.ReadCPSR(), egg.cpsr) ;
                else if ( i == 17 )
                    result += fmt::format("\t[X] pipeline[0]: mine={:x} ref={:x}\n",
                                          mine.fetchedBuffer[ !mine.fetchIdx ], egg.pipe[0]) ;
                else if ( i == 18 )
                    result += fmt::format("\t[X] pipeline[1]: mine={:x} ref={:x}\n",
                                          mine.fetchedBuffer[ mine.fetchIdx ], egg.pipe[1]) ;
            } // if
        } // for

        return result ;
    }

    virtual void SetUp() override {
        EggInit();
    }

    void EggInit() {
        const int argc = 2 ;
        static const char* argv[ argc ] = {
                "",
                testRomPath
        } ;

        core::init(argc, argv);
        std::copy(biosData.begin(), biosData.end(), mmu.bios.data.begin());
        core::reset();
    }

    void EggRun(Arm& egg_local, uint32_t instruction) {
        uint32_t inst_hash = hashArm(instruction);
        egg_local.regs[15] = (egg_local.regs[15] + 4) & ~0x3;
        egg_local.pipe[0] = egg_local.pipe[1];
        egg_local.pipe[1] = egg_local.readWord(egg_local.gprs[15]);
        std::invoke(egg_local.instr_arm[inst_hash], &egg_local, instruction);
    }

    void CpuPC_Reset(Arm& egg_local, gg_core::gg_cpu::CPU& local_cpu) {
        egg_local.regs[15] = 0 ;
        local_cpu._regs[15] = 0 ;
    }
};


static constexpr std::array<const char *, 16> regNames{
        "r0", "r1", "r2", "r3", "r4", "r5",
        "r6", "r7", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15"
};

static constexpr std::array<const char *, 4> shiftNames{
        "lsl", "lsr", "asr", "ror"
};

template <typename A, size_t... Is, typename... RS, typename... VS>
void FillRegs_Impl(A& regs, std::tuple<RS...>& R, std::tuple<VS...>& V, std::index_sequence<Is...>) {
    ((regs[std::get<Is>(R)] = std::get<Is>(V)), ...) ;
}

template <typename A, typename... RS, typename... VS>
void FillRegs(A& regs, std::tuple<RS...>& R, std::tuple<VS...>& V) {
    constexpr size_t reg_idx_number = sizeof...(RS);
    constexpr size_t field_number = sizeof...(VS);
    static_assert(reg_idx_number == field_number) ;

    FillRegs_Impl(regs, R, V, std::make_index_sequence<reg_idx_number>{});
}

enum F_Type {
    Cond, I, OpCode, S, Rn, Rd, ShiftType, ShiftAmount, Rm, Rs, Rotate, Imm,
    U, A, RdHi, RdLo, L, Offset, B, P, W, H, RegList
};

template <F_Type F, typename V>
uint32_t ALUInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::S) {
        static_assert(std::is_same_v<V, bool>, "Type missmatch") ;
        result |= value << 20 ;
    } // if
    else if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::OpCode) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_DataProcess>) ;
        result |= value << 21 ;
    } // else if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16 ;
    } // else if
    else if constexpr (F == F_Type::Rd) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12 ;
    } // else if
    else if constexpr (F == F_Type::Rm) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value ;
    } // else if
    else if constexpr (F == F_Type::Imm) {
        result |= (1 << 25) | value ;
    } // else if
    else if constexpr (F == F_Type::Rs) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= (1 << 4) | (value << 8) ;
    } // else if
    else if constexpr (F == F_Type::Rotate) {
        static_assert(std::is_integral_v<V>) ;
        result |= value << 8 ;
    } // else if
    else if constexpr (F == F_Type::ShiftType) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_ShiftType>) ;
        result |= value << 5 ;
    } // else if
    else if constexpr (F == F_Type::ShiftAmount) {
        static_assert(std::is_integral_v<V>) ;
        result |= value << 7 ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeALUInstruction(Vs... values) {
    return (ALUInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t MULInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::S) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 20 ;
    } // if
    else if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::A) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 21 ;
    } // else if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12 ;
    } // else if
    else if constexpr (F == F_Type::Rd) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16 ;
    } // else if
    else if constexpr (F == F_Type::Rm) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value ;
    } // else if
    else if constexpr (F == F_Type::Rs) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 8 ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeMULInstruction(Vs... values) {
    constexpr uint32_t mulBase = 0x00000090 ;
    return mulBase | (MULInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t MULLInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::S) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 20 ;
    } // if
    else if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::U) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 22 ;
    } // else if
    else if constexpr (F == F_Type::A) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 21 ;
    } // else if
    else if constexpr (F == F_Type::RdHi) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16 ;
    } // else if
    else if constexpr (F == F_Type::RdLo) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12 ;
    } // else if
    else if constexpr (F == F_Type::Rm) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value ;
    } // else if
    else if constexpr (F == F_Type::Rs) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 8 ;
    } // else if
    else
        gg_core::Unreachable() ;

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeMULLInstruction(Vs... values) {
    constexpr uint32_t mullBase = 0x00800090 ;
    return mullBase | (MULLInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t BranchInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::L) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 24 ;
    } // if
    else if constexpr (F == F_Type::Offset) {
        result |= value ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeBranchInstruction(Vs... values) {
    constexpr uint32_t mullBase = 0x0a000000 ;
    return mullBase | (BranchInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t SwpInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::B) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 22 ;
    } // if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16;
    } // else if
    else if constexpr (F == F_Type::Rd) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12;
    } // else if
    else if constexpr (F == F_Type::Rm) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeSwapInstruction(Vs... values) {
    constexpr uint32_t swpBase = 0x01000090 ;
    return swpBase | (SwpInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t SingleTransferInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::I) {
        result |= (value & 0x1) << 25 ;
    } // if
    else if constexpr (F == F_Type::P) {
        result |= (value & 0x1) << 24;
    } // else if
    else if constexpr (F == F_Type::U) {
        result |= (value & 0x1) << 23;
    } // else if
    else if constexpr (F == F_Type::B) {
        result |= (value & 0x1) << 22;
    } // else if
    else if constexpr (F == F_Type::W) {
        result |= (value & 0x1) << 21;
    } // else if
    else if constexpr (F == F_Type::L) {
        result |= (value & 0x1) << 20;
    } // else if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16;
    } // else if
    else if constexpr (F == F_Type::Rd) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12;
    } // else if
    else if constexpr (F == F_Type::Imm || F == F_Type::Rm) {
        result |= value ;
    } // else if
    else if constexpr (F == F_Type::ShiftType) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_ShiftType>) ;
        result |= value << 5 ;
    } // else if
    else if constexpr (F == F_Type::ShiftAmount) {
        static_assert(std::is_integral_v<V>) ;
        result |= value << 7 ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeSingleTransferInstruction(Vs... values) {
    constexpr uint32_t instrBase = 0x04000000 ;
    return instrBase | (SingleTransferInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t HalfTransferInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::P) {
        result |= (value & 0x1) << 24 ;
    } // if
    else if constexpr (F == F_Type::U) {
        result |= (value & 0x1) << 23;
    } // else if
    else if constexpr (F == F_Type::W) {
        result |= (value & 0x1) << 21;
    } // else if
    else if constexpr (F == F_Type::L) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 20;
    } // else if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16;
    } // else if
    else if constexpr (F == F_Type::Rd) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 12;
    } // else if
    else if constexpr (F == F_Type::S) {
        result |= value << 6;
    } // else if
    else if constexpr (F == F_Type::H) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 5;
    } // else if
    else if constexpr (F == F_Type::Rm) {
        result |= value ;
    } // else if
    else if constexpr (F == F_Type::Offset) {
        result |= ((value & 0xf0) << 4);
        result |= (value & 0xf) ;
        result |= (1 << 22) ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeHalfTransferInstruction(Vs... values) {
    constexpr uint32_t instrBase = 0x90 ;
    return instrBase | (HalfTransferInstruction<Fs>(values) | ...) ;
}

template <F_Type F, typename V>
uint32_t BlockTransferInstruction(V value) {
    uint32_t result = 0 ;
    if constexpr (F == F_Type::Cond) {
        static_assert(std::is_same_v<V, gg_core::gg_cpu::E_CondName>) ;
        result |= value << 28 ;
    } // else if
    else if constexpr (F == F_Type::P) {
        result |= (value & 0x1) << 24 ;
    } // if
    else if constexpr (F == F_Type::U) {
        result |= (value & 0x1) << 23;
    } // else if
    else if constexpr (F == F_Type::S) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 22 ;
    } // else if
    else if constexpr (F == F_Type::W) {
        result |= (value & 0x1) << 21;
    } // else if
    else if constexpr (F == F_Type::L) {
        static_assert(std::is_same_v<V, bool>, "Type mismatch") ;
        result |= value << 20;
    } // else if
    else if constexpr (F == F_Type::Rn) {
        static_assert(std::is_integral_v<V> || std::is_same_v<V, gg_core::gg_cpu::E_RegName>) ;
        result |= value << 16;
    } // else if
    else if constexpr (F == F_Type::RegList) {
        result |= value & 0xffff ;
    } // else if
    else
        gg_core::Unreachable();

    return result ;
}

template <F_Type... Fs, typename... Vs>
uint32_t MakeBlockTransferInstruction(Vs... values) {
    constexpr uint32_t instrBase = 0x08000000 ;
    return instrBase | (BlockTransferInstruction<Fs>(values) | ...) ;
}

using WorkerResult = std::pair<std::string, std::future<unsigned int>> ;

#endif //GGTEST_GG_TEST_H

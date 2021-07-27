//
// Created by orzgg on 2021-07-11.
//

#ifndef GGTEST_ARM_ENCODER_H
#define GGTEST_ARM_ENCODER_H

namespace gg_core::gg_cpu {
    enum F_Type {
        Cond, I, OpCode, S, Rn, Rd, ShiftType, ShiftAmount, Rm, Rs, Rotate, Imm,
        U, A, RdHi, RdLo, L, Offset, B, P, W, H, RegList
    };

    template <F_Type F, typename V>
    constexpr uint32_t ALUInstruction(V value) {
        uint32_t result = 0 ;
        if constexpr (F == F_Type::S)
            result |= value << 20 ;
        else if constexpr (F == F_Type::Cond)
            result |= value << 28 ;
        else if constexpr (F == F_Type::OpCode)
            result |= value << 21 ;
        else if constexpr (F == F_Type::Rn)
            result |= value << 16 ;
        else if constexpr (F == F_Type::Rd)
            result |= value << 12 ;
        else if constexpr (F == F_Type::Rm)
            result |= value ;
        else if constexpr (F == F_Type::Imm)
            result |= (1 << 25) | value ;
        else if constexpr (F == F_Type::Rs)
            result |= (1 << 4) | (value << 8) ;
        else if constexpr (F == F_Type::Rotate)
            result |= value << 8 ;
        else if constexpr (F == F_Type::ShiftType)
            result |= value << 5 ;
        else if constexpr (F == F_Type::ShiftAmount)
            result |= value << 7 ;
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
}

#endif //GGTEST_ARM_ENCODER_H

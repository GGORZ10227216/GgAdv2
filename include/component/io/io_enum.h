//
// Created by buildmachine on 2021-03-11.
//

#ifndef GGTEST_IO_ENUM_H
#define GGTEST_IO_ENUM_H

namespace gg_core::gg_io {
    struct IO;

    enum class E_IO_AccessMode {
        R = 0, W = 1, RW = 2, U = 3
    };

    using IO_RegInfo = std::tuple<uint8_t, uint32_t, E_IO_AccessMode>;
    using IO_AccessHandler = bool (*)();
    using IO_RW_Policy = std::pair<IO_AccessHandler, IO_AccessHandler>;
    using IO_Policy = std::tuple<IO_RW_Policy, IO_RW_Policy, IO_RW_Policy>;

    enum E_IOField {
        NAME_ADDR = 0, WIDTH = 1, ACCESS_MODE = 2
    };

    enum E_IOName {
        DISPCNT = 0x4000000,
        DISPSTAT = 0x4000004,
        VCOUNT = 0x4000006,
        BG0CNT = 0x4000008,
        BG1CNT = 0x400000a,
        BG2CNT = 0x400000c,
        BG3CNT = 0x400000e,
        BG0HOFS = 0x4000010,
        BG0VOFS = 0x4000012,
        BG1HOFS = 0x4000014,
        BG1VOFS = 0x4000016,
        BG2HOFS = 0x4000018,
        BG2VOFS = 0x400001a,
        BG3HOFS = 0x400001c,
        BG3VOFS = 0x400001e,
        BG2PA = 0x4000020,
        BG2PB = 0x4000022,
        BG2PC = 0x4000024,
        BG2PD = 0x4000026,
        BG2X = 0x4000028,
        BG2Y = 0x400002c,
        BG3PA = 0x4000030,
        BG3PB = 0x4000032,
        BG3PC = 0x4000034,
        BG3PD = 0x4000036,
        BG3X = 0x4000038,
        BG3Y = 0x400003c,
        WIN0H = 0x4000040,
        WIN1H = 0x4000042,
        WIN0V = 0x4000044,
        WIN1V = 0x4000046,
        WININ = 0x4000048,
        WINOUT = 0x400004a,
        MOSAIC = 0x400004c,
        BLDCNT = 0x4000050,
        BLDALPHA = 0x4000052,
        BLDY = 0x4000054,
        SOUND1CNT_L = 0x4000060,
        SOUND1CNT_H = 0x4000062,
        SOUND1CNT_X = 0x4000064,
        SOUND2CNT_L = 0x4000068,
        SOUND2CNT_H = 0x400006c,
        SOUND3CNT_L = 0x4000070,
        SOUND3CNT_H = 0x4000072,
        SOUND3CNT_X = 0x4000074,
        SOUND4CNT_L = 0x4000078,
        SOUND4CNT_H = 0x400007c,
        SOUNDCNT_L = 0x4000080,
        SOUNDCNT_H = 0x4000082,
        SOUNDCNT_X = 0x4000084,
        SOUNDBIAS = 0x4000088,
        WAVE_RAM0_L = 0x4000090,
        WAVE_RAM0_H = 0x4000092,
        WAVE_RAM1_L = 0x4000094,
        WAVE_RAM1_H = 0x4000096,
        WAVE_RAM2_L = 0x4000098,
        WAVE_RAM2_H = 0x400009a,
        WAVE_RAM3_L = 0x400009c,
        WAVE_RAM3_H = 0x400009e,
        FIFO_A = 0x40000a0,
        FIFO_B = 0x40000a4,
        DMA0SAD = 0x40000b0,
        DMA0DAD = 0x40000b4,
        DMA0CNT_L = 0x40000b8,
        DMA0CNT_H = 0x40000ba,
        DMA1SAD = 0x40000bc,
        DMA1DAD = 0x40000c0,
        DMA1CNT_L = 0x40000c4,
        DMA1CNT_H = 0x40000c6,
        DMA2SAD = 0x40000c8,
        DMA2DAD = 0x40000cc,
        DMA2CNT_L = 0x40000d0,
        DMA2CNT_H = 0x40000d2,
        DMA3SAD = 0x40000d4,
        DMA3DAD = 0x40000d8,
        DMA3CNT_L = 0x40000dc,
        DMA3CNT_H = 0x40000de,
        TM0CNT_L = 0x4000100,
        TM0CNT_H = 0x4000102,
        TM1CNT_L = 0x4000104,
        TM1CNT_H = 0x4000106,
        TM2CNT_L = 0x4000108,
        TM2CNT_H = 0x400010a,
        TM3CNT_L = 0x400010c,
        TM3CNT_H = 0x400010e,
        SIODATA32 = 0x4000120,
        SIOMULTI0 = 0x4000120,
        SIOMULTI1 = 0x4000122,
        SIOMULTI2 = 0x4000124,
        SIOMULTI3 = 0x4000126,
        SIOCNT = 0x4000128,
        SIOMLT_SEND = 0x400012a,
        SIODATA8 = 0x400012a,
        KEYINPUT = 0x4000130,
        KEYCNT = 0x4000132,
        RCNT = 0x4000134,
        JOYCNT = 0x4000140,
        JOY_RECV = 0x4000150,
        JOY_TRANS = 0x4000154,
        JOYSTAT = 0x4000158,
        IE = 0x4000200,
        IF = 0x4000202,
        WAITCNT = 0x4000204,
        IME = 0x4000208,
        POSTFLG = 0x4000300,
        HALTCNT = 0x4000301
    };

    constexpr static auto IOReg_table = gg_core::make_array(
            std::make_tuple(DISPCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(DISPSTAT, 2, E_IO_AccessMode::RW),
            std::make_tuple(VCOUNT, 2, E_IO_AccessMode::R),
            std::make_tuple(BG0CNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(BG1CNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(BG2CNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(BG3CNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(BG0HOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG0VOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG1HOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG1VOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2HOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2VOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3HOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3VOFS, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2PA, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2PB, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2PC, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2PD, 2, E_IO_AccessMode::W),
            std::make_tuple(BG2X, 4, E_IO_AccessMode::W),
            std::make_tuple(BG2Y, 4, E_IO_AccessMode::W),
            std::make_tuple(BG3PA, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3PB, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3PC, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3PD, 2, E_IO_AccessMode::W),
            std::make_tuple(BG3X, 4, E_IO_AccessMode::W),
            std::make_tuple(BG3Y, 4, E_IO_AccessMode::W),
            std::make_tuple(WIN0H, 2, E_IO_AccessMode::W),
            std::make_tuple(WIN1H, 2, E_IO_AccessMode::W),
            std::make_tuple(WIN0V, 2, E_IO_AccessMode::W),
            std::make_tuple(WIN1V, 2, E_IO_AccessMode::W),
            std::make_tuple(WININ, 2, E_IO_AccessMode::RW),
            std::make_tuple(WINOUT, 2, E_IO_AccessMode::RW),
            std::make_tuple(MOSAIC, 2, E_IO_AccessMode::W),
            std::make_tuple(BLDCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(BLDALPHA, 2, E_IO_AccessMode::RW),
            std::make_tuple(BLDY, 2, E_IO_AccessMode::W),
            std::make_tuple(SOUND1CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND1CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND1CNT_X, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND2CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND2CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND3CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND3CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND3CNT_X, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND4CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUND4CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUNDCNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUNDCNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUNDCNT_X, 2, E_IO_AccessMode::RW),
            std::make_tuple(SOUNDBIAS, 2, E_IO_AccessMode::R),
            std::make_tuple(WAVE_RAM0_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM0_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM1_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM1_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM2_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM2_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM3_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAVE_RAM3_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(FIFO_A, 4, E_IO_AccessMode::W),
            std::make_tuple(FIFO_B, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA0SAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA0DAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA0CNT_L, 2, E_IO_AccessMode::W),
            std::make_tuple(DMA0CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(DMA1SAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA1DAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA1CNT_L, 2, E_IO_AccessMode::W),
            std::make_tuple(DMA1CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(DMA2SAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA2DAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA2CNT_L, 2, E_IO_AccessMode::W),
            std::make_tuple(DMA2CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(DMA3SAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA3DAD, 4, E_IO_AccessMode::W),
            std::make_tuple(DMA3CNT_L, 2, E_IO_AccessMode::W),
            std::make_tuple(DMA3CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM0CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM0CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM1CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM1CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM2CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM2CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM3CNT_L, 2, E_IO_AccessMode::RW),
            std::make_tuple(TM3CNT_H, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIODATA32, 4, E_IO_AccessMode::RW),
            std::make_tuple(SIOMULTI0, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIOMULTI1, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIOMULTI2, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIOMULTI3, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIOCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIOMLT_SEND, 2, E_IO_AccessMode::RW),
            std::make_tuple(SIODATA8, 2, E_IO_AccessMode::RW),
            std::make_tuple(KEYINPUT, 2, E_IO_AccessMode::R),
            std::make_tuple(KEYCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(RCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(JOYCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(JOY_RECV, 4, E_IO_AccessMode::RW),
            std::make_tuple(JOY_TRANS, 4, E_IO_AccessMode::RW),
            std::make_tuple(JOYSTAT, 2, E_IO_AccessMode::R),
            std::make_tuple(IE, 2, E_IO_AccessMode::RW),
            std::make_tuple(IF, 2, E_IO_AccessMode::RW),
            std::make_tuple(WAITCNT, 2, E_IO_AccessMode::RW),
            std::make_tuple(IME, 2, E_IO_AccessMode::RW),
            std::make_tuple(POSTFLG, 1, E_IO_AccessMode::RW),
            std::make_tuple(HALTCNT, 1, E_IO_AccessMode::W)
    );

    template<size_t I>
    constexpr static int SetPolicy(std::array<uint8_t, 0x3ff>& tmp) {
        constexpr unsigned width = std::get<E_IOField::WIDTH>(IOReg_table[I]) ;
        constexpr unsigned addr = std::get<E_IOField::NAME_ADDR>(IOReg_table[I]) - 0x4000000 ;
        constexpr E_IO_AccessMode mode = std::get<E_IOField::ACCESS_MODE>(IOReg_table[I]) ;

        tmp[ addr ] = static_cast<uint8_t> (mode) ;
        if constexpr (width >= 2)
            tmp[ addr+1 ] = static_cast<uint8_t> (mode) ;

        if constexpr (width == 4) {
            tmp[ addr+2 ] = static_cast<uint8_t> (mode) ;
            tmp[ addr+3 ] = static_cast<uint8_t> (mode) ;
        } // else if

        return 0 ;
    }

    template <size_t... Idx>
    constexpr static std::array<uint8_t, 0x3ff> SetPolicies(std::index_sequence<Idx...>) {
        std::array<uint8_t, 0x3ff> tmp {};
        tmp.fill(static_cast<uint8_t>(E_IO_AccessMode::U)) ;

        (SetPolicy<Idx>(tmp) | ...);

        return tmp ;
    }

    constexpr static std::array<uint8_t, 0x3ff> policyTable =
        SetPolicies(std::make_index_sequence<IOReg_table.size()>{});
}

#endif //GGTEST_IO_ENUM_H

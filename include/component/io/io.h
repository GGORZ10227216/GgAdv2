//
// Created by orzgg on 2020-06-30.
//

#include <exception>
#include <memory>

#include <io_enum.h>

#ifndef TEST_IOREG_TYPE_H
#define TEST_IOREG_TYPE_H

namespace gg_core::gg_io {
    struct IO {
        template<unsigned REG_WIDTH, uint32_t ADDR, IO_AccessMode M, gg_mem::E_AccessType AT, unsigned REQUIRED_WIDTH>
        static uint8_t &AccessRef(IO* self) {
            if constexpr ((M == IO_AccessMode::W && AT == gg_mem::READ) || (M == IO_AccessMode::R && AT == gg_mem::WRITE))
                throw std::logic_error("Access not allowed");
            else {
                if constexpr (REQUIRED_WIDTH <= REG_WIDTH) {
                    // fixme: what if read DWORD from a BYTE wide reg?
                    return std::get<ADDR - 0x04000000>(self->_data);
                } // if
                else
                    throw std::logic_error("Request an invalid reference that is wider than this IO register");
            } // else
        } // Read()

        template <size_t... Idx>
        constexpr auto MakeAccessTable(std::index_sequence<Idx...>) ->
            std::array<uint8_t&(IO::*)(), sizeof...(Idx)>
        {
            // still not correct, use NAME_ADDR as index instead.
            constexpr std::array<IO_Policy, 0x3ff> AccessPolicy {
                std::make_tuple(
                    std::make_pair(
                            AccessRef<
                                static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                                std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                                std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                                gg_mem::READ,
                                1
                            >,
                            AccessRef<
                                static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                                std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                                std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                                gg_mem::WRITE,
                                1
                            >
                    ),
                    std::make_pair(
                            AccessRef<
                                    static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                                    std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                                    std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                                    gg_mem::READ,
                                    2
                            >,
                            AccessRef<
                                    static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                                    std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                                    std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                                    gg_mem::WRITE,
                                    2
                            >
                    ),
                    std::make_pair(
                            AccessRef<
                                static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                                std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                                std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                                gg_mem::READ,
                                4
                            >,
                        AccessRef<
                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
                            std::get<E_IOField::NAME_ADDR>(IOReg_table[Idx]),
                            std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
                            gg_mem::WRITE,
                            4
                        >
                    )
                )...
            };
        }


//        template<gg_mem::E_AccessType AT, typename REQUIRED_WIDTH> uint8_t &DISPCNT ()
//            { return AccessRef<uint16_t, 0x4000000, IO_AccessMode::RW, AT, REQUIRED_WIDTH>() ;}
//        IOReg_t<uint16_t, 0x4000004, IO_AccessMode::RW> DISPSTAT{_data};
//        IOReg_t<uint16_t, 0x4000006, IO_AccessMode::R> VCOUNT{_data};
//        IOReg_t<uint16_t, 0x4000008, IO_AccessMode::RW> BG0CNT{_data};
//        IOReg_t<uint16_t, 0x400000a, IO_AccessMode::RW> BG1CNT{_data};
//        IOReg_t<uint16_t, 0x400000c, IO_AccessMode::RW> BG2CNT{_data};
//        IOReg_t<uint16_t, 0x400000e, IO_AccessMode::RW> BG3CNT{_data};
//        IOReg_t<uint16_t, 0x4000010, IO_AccessMode::W> BG0HOFS{_data};
//        IOReg_t<uint16_t, 0x4000012, IO_AccessMode::W> BG0VOFS{_data};
//        IOReg_t<uint16_t, 0x4000014, IO_AccessMode::W> BG1HOFS{_data};
//        IOReg_t<uint16_t, 0x4000016, IO_AccessMode::W> BG1VOFS{_data};
//        IOReg_t<uint16_t, 0x4000018, IO_AccessMode::W> BG2HOFS{_data};
//        IOReg_t<uint16_t, 0x400001a, IO_AccessMode::W> BG2VOFS{_data};
//        IOReg_t<uint16_t, 0x400001c, IO_AccessMode::W> BG3HOFS{_data};
//        IOReg_t<uint16_t, 0x400001e, IO_AccessMode::W> BG3VOFS{_data};
//        IOReg_t<uint16_t, 0x4000020, IO_AccessMode::W> BG2PA{_data};
//        IOReg_t<uint16_t, 0x4000022, IO_AccessMode::W> BG2PB{_data};
//        IOReg_t<uint16_t, 0x4000024, IO_AccessMode::W> BG2PC{_data};
//        IOReg_t<uint16_t, 0x4000026, IO_AccessMode::W> BG2PD{_data};
//        IOReg_t<uint32_t, 0x4000028, IO_AccessMode::W> BG2X{_data};
//        IOReg_t<uint32_t, 0x400002c, IO_AccessMode::W> BG2Y{_data};
//        IOReg_t<uint16_t, 0x4000030, IO_AccessMode::W> BG3PA{_data};
//        IOReg_t<uint16_t, 0x4000032, IO_AccessMode::W> BG3PB{_data};
//        IOReg_t<uint16_t, 0x4000034, IO_AccessMode::W> BG3PC{_data};
//        IOReg_t<uint16_t, 0x4000036, IO_AccessMode::W> BG3PD{_data};
//        IOReg_t<uint32_t, 0x4000038, IO_AccessMode::W> BG3X{_data};
//        IOReg_t<uint32_t, 0x400003c, IO_AccessMode::W> BG3Y{_data};
//        IOReg_t<uint16_t, 0x4000040, IO_AccessMode::W> WIN0H{_data};
//        IOReg_t<uint16_t, 0x4000042, IO_AccessMode::W> WIN1H{_data};
//        IOReg_t<uint16_t, 0x4000044, IO_AccessMode::W> WIN0V{_data};
//        IOReg_t<uint16_t, 0x4000046, IO_AccessMode::W> WIN1V{_data};
//        IOReg_t<uint16_t, 0x4000048, IO_AccessMode::RW> WININ{_data};
//        IOReg_t<uint16_t, 0x400004a, IO_AccessMode::RW> WINOUT{_data};
//        IOReg_t<uint16_t, 0x400004c, IO_AccessMode::W> MOSAIC{_data};
//        IOReg_t<uint16_t, 0x4000050, IO_AccessMode::RW> BLDCNT{_data};
//        IOReg_t<uint16_t, 0x4000052, IO_AccessMode::RW> BLDALPHA{_data};
//        IOReg_t<uint16_t, 0x4000054, IO_AccessMode::W> BLDY{_data};
    private :
        std::array<uint8_t, 0x3ff> _data;
    };
}

#endif //TEST_IOREG_TYPE_H
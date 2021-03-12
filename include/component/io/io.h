//
// Created by orzgg on 2020-06-30.
//

#include <exception>
#include <memory>

#include <io_enum.h>

#ifndef TEST_IOREG_TYPE_H
#define TEST_IOREG_TYPE_H

namespace gg_core::gg_io {
    class IO {
        using IO_Policies_t = std::array<IO_Policy, 0x3ff> ;
        IO_Policies_t _data{};

        template<unsigned REG_WIDTH, IO_AccessMode M, gg_mem::E_AccessType AT, unsigned REQUIRED_WIDTH>
        static bool AccessPolicy() {
            if constexpr ((M == IO_AccessMode::W && AT == gg_mem::READ) || (M == IO_AccessMode::R && AT == gg_mem::WRITE))
                return false ; // "Access not allowed"
            else {
                if constexpr (REQUIRED_WIDTH <= REG_WIDTH) {
                    // fixme: what if read DWORD from a BYTE wide reg?
                    return true;
                } // if
                else
                    return false ; // "Request an invalid reference that is wider than this IO register"
            } // else
        } // Read()

        constexpr static IO_Policy _ILLEGAL {
                IO_Policy(
                        IO_RW_Policy(
                                [](){return false;},
                                [](){return false;}
                        ),
                        IO_RW_Policy(
                                [](){return false;},
                                [](){return false;}
                        ),
                        IO_RW_Policy(
                                [](){return false;},
                                [](){return false;}
                        )
                )
        } ;

        template <size_t... Idx>
        constexpr static auto MakeAccessPolicyTable(std::index_sequence<Idx...>)
        {
            std::array<IO_Policy, sizeof...(Idx)> tmp ;
            tmp.fill(_ILLEGAL) ;

//            {
//                IO_Policy(
//                        IO_RW_Policy(
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::READ,
//                                        1
//                                >,
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::WRITE,
//                                        1
//                                >
//                        ),
//                        IO_RW_Policy(
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::READ,
//                                        2
//                                >,
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::WRITE,
//                                        2
//                                >
//                        ),
//                        IO_RW_Policy(
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::READ,
//                                        4
//                                >,
//                                AccessPolicy<
//                                        static_cast<unsigned>(std::get<E_IOField::WIDTH>(IOReg_table[Idx])),
//                                        std::get<E_IOField::ACCESS_MODE>(IOReg_table[Idx]),
//                                        gg_mem::WRITE,
//                                        4
//                                >
//                        )
//                )...
//            }

            return tmp ;
        }

    public :
        constexpr static IO_Policies_t table = MakeAccessPolicyTable(std::make_index_sequence<0x3ff>{}) ;
    };
}

#endif //TEST_IOREG_TYPE_H
//
// Created by orzgg on 2020-06-30.
//

#include <exception>
#include <memory>

#include <io_enum.h>

#ifndef TEST_IOREG_TYPE_H
#define TEST_IOREG_TYPE_H

namespace gg_core::gg_io {
//    template <E_IOName IO_ADDR, size_t WIDTH, E_IO_AccessMode MODE>
//    struct IO_Field {
//        auto Read() {
//
//        }
//    };
//
//    struct IO {
//        template <E_IOName IO_ADDR, size_t WIDTH, E_IO_AccessMode MODE>
//        using IO_Type = IO_Field<IO_ADDR, WIDTH, MODE> ;
//
//        IO(uint8_t* ioreg) :
//            _ioreg(ioreg)
//        {
//
//        } // IO()
//
//        IO_Field<E_IOName::DISPCNT, 2, E_IO_AccessMode::RW> DISPCNT = [&]() {
//            constexpr auto [name, width, mode] = IOReg_table[0] ;
//            return IO_Field<name,width,mode>() ;
//        }();
//
//    private :
//        const uint8_t* _ioreg = nullptr ;
//    };
}

#endif //TEST_IOREG_TYPE_H
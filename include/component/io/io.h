//
// Created by orzgg on 2020-06-30.
//

#include <exception>
#include <memory>

#ifndef TEST_IOREG_TYPE_H
#define TEST_IOREG_TYPE_H

namespace gg_core::gg_io {
    enum class AccessMode {
        R = 0, W = 1, RW = 2
    };

    using RegCallback_t = void(*)(const void*);

    template<typename REG_WIDTH, uint32_t ADDR, AccessMode M>
    struct IOReg_t {
        template<typename IO_MEM_TYPE>
        IOReg_t(IO_MEM_TYPE regMem):
                _value(reinterpret_cast<REG_WIDTH &>(regMem[ADDR - 0x04000000])) {

        }

        template<gg_mem::E_AccessType AT, typename REQUIRED_WIDTH>
        uint8_t &AccessRef() const {
            if constexpr ((M == AccessMode::W && AT == gg_mem::READ) || (M == AccessMode::R && AT == gg_mem::WRITE))
                throw std::logic_error("Access not allowed");
            else {
                if constexpr (sizeof(REQUIRED_WIDTH) <= sizeof(REG_WIDTH)) {
                    // fixme: what if read DWORD from a BYTE wide reg?
                    return reinterpret_cast<uint8_t &> (_value);
                } // if
                else
                    throw std::logic_error("Request an invalid reference that is wider than this IO register");
            } // else
        } // Read()

    private:
        REG_WIDTH &_value;
    };

    struct IO {
        std::array<uint8_t, 0x3ff> _data;

        IOReg_t<uint16_t, 0x4000000, AccessMode::RW> DISPCNT{_data};
        IOReg_t<uint16_t, 0x4000004, AccessMode::RW> DISPSTAT{_data};
        IOReg_t<uint16_t, 0x4000006, AccessMode::R> VCOUNT{_data};
        IOReg_t<uint16_t, 0x4000008, AccessMode::RW> BG0CNT{_data};
        IOReg_t<uint16_t, 0x400000a, AccessMode::RW> BG1CNT{_data};
        IOReg_t<uint16_t, 0x400000c, AccessMode::RW> BG2CNT{_data};
        IOReg_t<uint16_t, 0x400000e, AccessMode::RW> BG3CNT{_data};
        IOReg_t<uint16_t, 0x4000010, AccessMode::W> BG0HOFS{_data};
        IOReg_t<uint16_t, 0x4000012, AccessMode::W> BG0VOFS{_data};
        IOReg_t<uint16_t, 0x4000014, AccessMode::W> BG1HOFS{_data};
        IOReg_t<uint16_t, 0x4000016, AccessMode::W> BG1VOFS{_data};
        IOReg_t<uint16_t, 0x4000018, AccessMode::W> BG2HOFS{_data};
        IOReg_t<uint16_t, 0x400001a, AccessMode::W> BG2VOFS{_data};
        IOReg_t<uint16_t, 0x400001c, AccessMode::W> BG3HOFS{_data};
        IOReg_t<uint16_t, 0x400001e, AccessMode::W> BG3VOFS{_data};
        IOReg_t<uint16_t, 0x4000020, AccessMode::W> BG2PA{_data};
        IOReg_t<uint16_t, 0x4000022, AccessMode::W> BG2PB{_data};
        IOReg_t<uint16_t, 0x4000024, AccessMode::W> BG2PC{_data};
        IOReg_t<uint16_t, 0x4000026, AccessMode::W> BG2PD{_data};
        IOReg_t<uint32_t, 0x4000028, AccessMode::W> BG2X{_data};
        IOReg_t<uint32_t, 0x400002c, AccessMode::W> BG2Y{_data};
        IOReg_t<uint16_t, 0x4000030, AccessMode::W> BG3PA{_data};
        IOReg_t<uint16_t, 0x4000032, AccessMode::W> BG3PB{_data};
        IOReg_t<uint16_t, 0x4000034, AccessMode::W> BG3PC{_data};
        IOReg_t<uint16_t, 0x4000036, AccessMode::W> BG3PD{_data};
        IOReg_t<uint32_t, 0x4000038, AccessMode::W> BG3X{_data};
        IOReg_t<uint32_t, 0x400003c, AccessMode::W> BG3Y{_data};
        IOReg_t<uint16_t, 0x4000040, AccessMode::W> WIN0H{_data};
        IOReg_t<uint16_t, 0x4000042, AccessMode::W> WIN1H{_data};
        IOReg_t<uint16_t, 0x4000044, AccessMode::W> WIN0V{_data};
        IOReg_t<uint16_t, 0x4000046, AccessMode::W> WIN1V{_data};
        IOReg_t<uint16_t, 0x4000048, AccessMode::RW> WININ{_data};
        IOReg_t<uint16_t, 0x400004a, AccessMode::RW> WINOUT{_data};
        IOReg_t<uint16_t, 0x400004c, AccessMode::W> MOSAIC{_data};
        IOReg_t<uint16_t, 0x4000050, AccessMode::RW> BLDCNT{_data};
        IOReg_t<uint16_t, 0x4000052, AccessMode::RW> BLDALPHA{_data};
        IOReg_t<uint16_t, 0x4000054, AccessMode::W> BLDY{_data};
    };
}

#endif //TEST_IOREG_TYPE_H
//
// Created by orzgg on 2021-04-04.
//

#include <mem_enum.h>

#ifndef GGTEST_EEPROM_HPP
#define GGTEST_EEPROM_HPP

namespace gg_core::gg_mem {
    struct EEPROM {
        EEPROM(unsigned& c, E_SaveType t) : _cycleCounter(c) {
            if (t == E_EEPROM512B) {
                addrWidth = 6 ;
                _data.resize(64) ;
            } // if
            else if (t == E_EEPROM8K){
                addrWidth = 14 ;
                _data.resize(1024) ;
            } // else
            else {
                GGLOG("Unsupported EEPROM size") ;
                exit(-1);
            }
        }

        void SendCmd(unsigned cmd) {
            bool cmdBit = cmd & 0b1 ;
            switch (mode) {
                case LISTENING:
                    _accessMode = (_accessMode << 1) | cmdBit ;
                    if (++_nthBit == 2) {
                        mode = RECEIVING_ADDR ;
                        _nthBit = 0 ;
                    } // if
                    break ;
                case RECEIVING_ADDR:
                    _addr = (_addr << 1) | cmdBit ;
                    if (++_nthBit == addrWidth) {
                        if (_accessMode == 0b11) {
                            mode = WAIT_CLOSE ;
                            _nthBit = 0 ;
                        } // if
                        else {
                            mode = RECEIVING_DATA ;
                            _data[ _addr ] = 0 ;
                            _cycleCounter += 108368 ; // cycles for EEPROM erasing
                            _nthBit = 0 ;
                        } // else
                    } // if
                    break ;
                case RECEIVING_DATA:
                    _data[ _addr ] <<= 1 ;
                    _data[ _addr ] |= cmdBit ;
                    if (++_nthBit == 64) {
                        mode = WAIT_CLOSE ;
                        _nthBit = 0 ;
                    } // if
                    break ;
                case WAIT_CLOSE:
                    if (cmdBit != 0)
                        gg_core::GGLOG("Invalid EEPROM command: End of transmission signal is not equal to 0") ;
                    else {
                        _ready = true ;
                        if (_accessMode == 0b11)
                            mode = TRANSMITTING ;
                        else {
                            mode = LISTENING ;
                        } // else
                    } // else
                    break ;
            } // switch
        } // SendCmd()

        uint16_t _ReadData(uint32_t chunkNum) {
            // todo: transmit 68bit in TRANSMITTING mode
            if (_ready) {
                _nthBit += 1 ;
                if (_nthBit < 4) {
                    return 0 ;
                } // if
                else if (_nthBit < 68) {
                    uint16_t result = 0 ;
                    result |= !!(_data[_addr] & (1 << _nthBit));
                    return result ;
                } // else
                else {
                    mode = LISTENING ;
                    _nthBit = 0 ;
                } // else
            } // if
            else {
                GGLOG("Reading data before command sent") ;
                return 0 ;
            } // else
        } // _ReadData()

    private :
        unsigned addrWidth = 0;
        unsigned& _cycleCounter ;
        enum E_WORK_MODE {LISTENING, RECEIVING_ADDR, RECEIVING_DATA, WAIT_CLOSE, TRANSMITTING} ;
        E_WORK_MODE mode = LISTENING ;

        uint16_t _addr = 0 ;
        uint8_t _nthBit = 0, _accessMode = 0 ;
        bool _ready = false ;

        std::vector<uint64_t> _data ;

        void _Reset() {
            _addr = 0 ;
            _nthBit = 0 ;
            _accessMode = LISTENING ;
        } // _Reset()
    };
}

#endif //GGTEST_EEPROM_HPP

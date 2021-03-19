//
// Created by buildmachine on 2021-03-19.
//

#include <span>
#include <vector>

#include <file_access.h>

#ifndef GGTEST_CARTRIDGE_H
#define GGTEST_CARTRIDGE_H

namespace gg_core {
    struct Header {
        using RomByte = const uint8_t ;

        Header(const uint8_t* romData):
            _romData(romData),
            entryPoint(romData, romData + 0x4),
            logo(romData + 0x4, romData + 0xa0),
            gameTitle(romData + 0xa0, romData + 0xac),
            gameCode(romData + 0xb0, romData + 0xb2),
            makerCode(romData + 0xb0, romData + 0xb2),
            fixedValue(romData + 0xb2, romData + 0xb3),
            mainUnitCode(romData + 0xb3, romData + 0xb4),
            deviceType(romData + 0xb4, romData + 0xb5),
            reservedArea(romData + 0xb5, romData + 0xbc),
            softwareVersion(romData + 0xbc, romData + 0xbd),
            checksum(romData + 0xbd, romData + 0xbe),
            reservedArea2(romData + 0xbe, romData + 0xc0),
            ramEntryPoint(romData + 0xc0, romData + 0xc4),
            bootMode(romData + 0xc4, romData + 0xc5),
            slaveID(romData + 0xc5, romData + 0xc6),
            reservedArea3(romData + 0xc6, romData + 0xe0),
            joybusEntryPoint(romData + 0xe0, romData + 0xe4)
        {}

        std::span<RomByte, 0x4> entryPoint ;
        std::span<RomByte, 0x9c> logo;
        std::span<RomByte, 0xc> gameTitle;
        std::span<RomByte, 0x4> gameCode;
        std::span<RomByte, 0x2> makerCode;
        std::span<RomByte, 0x1> fixedValue;
        std::span<RomByte, 0x1> mainUnitCode;
        std::span<RomByte, 0x1> deviceType;
        std::span<RomByte, 0x7> reservedArea;
        std::span<RomByte, 0x1> softwareVersion;
        std::span<RomByte, 0x1> checksum;
        std::span<RomByte, 0x2> reservedArea2;

        /*Multiboot*/
        std::span<RomByte, 0x4> ramEntryPoint;
        std::span<RomByte, 0x1> bootMode;
        std::span<RomByte, 0x1> slaveID;
        std::span<RomByte, 0x26> reservedArea3;
        std::span<RomByte, 0x4> joybusEntryPoint;
    private :
        const uint8_t *_romData;
    };

    class Cartridge {
    public:
        Cartridge() {

        }

        Cartridge(const char* pathStr) {
            using namespace std::filesystem;
            path romPath(pathStr) ;
            if (exists(romPath)) {
                romData = LoadFileToBuffer(romPath);
            } // if
            else {

            } // else
        }

    private :
        std::vector<uint8_t> romData ;
    };
}

#endif //GGTEST_CARTRIDGE_H

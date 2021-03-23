//
// Created by buildmachine on 2021-03-19.
//

#include <span>
#include <vector>

#include <file_access.h>

#ifndef GGTEST_CARTRIDGE_H
#define GGTEST_CARTRIDGE_H

namespace gg_core {
    enum E_SaveType {
        E_SRAM, E_EEPROM, E_FLASH64K, E_FLASH128K, E_UNKNOWN
    };

    struct Header {
        using RomByte = const uint8_t;

        Header(const uint8_t *romData) :
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
                joybusEntryPoint(romData + 0xe0, romData + 0xe4) {}

        bool Verify() {
            bool logoCheck = std::equal(logo.begin(), logo.end(), correctLogo.begin()) ;
            bool fixedValue_0xb2 = fixedValue[0] == 0x96 ;
            return logoCheck && fixedValue_0xb2 ;
        }

        std::span<RomByte, 0x4> entryPoint;
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

        constexpr static std::array<uint8_t, 0x9c> correctLogo{
                0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A, 0xA2, 0x21, 0x3D, 0x84, 0x82, 0x0A, 0x84, 0xE4, 0x09, 0xAD, 0x11,
                0x24, 0x8B, 0x98, 0xC0, 0x81, 0x7F, 0x21, 0xA3, 0x52, 0xBE, 0x19, 0x93, 0x09, 0xCE, 0x20, 0x10, 0x46,
                0x4A, 0x4A, 0xF8, 0x27, 0x31, 0xEC, 0x58, 0xC7, 0xE8, 0x33, 0x82, 0xE3, 0xCE, 0xBF, 0x85, 0xF4, 0xDF,
                0x94, 0xCE, 0x4B, 0x09, 0xC1, 0x94, 0x56, 0x8A, 0xC0, 0x13, 0x72, 0xA7, 0xFC, 0x9F, 0x84, 0x4D, 0x73,
                0xA3, 0xCA, 0x9A, 0x61, 0x58, 0x97, 0xA3, 0x27, 0xFC, 0x03, 0x98, 0x76, 0x23, 0x1D, 0xC7, 0x61, 0x03,
                0x04, 0xAE, 0x56, 0xBF, 0x38, 0x84, 0x00, 0x40, 0xA7, 0x0E, 0xFD, 0xFF, 0x52, 0xFE, 0x03, 0x6F, 0x95,
                0x30, 0xF1, 0x97, 0xFB, 0xC0, 0x85, 0x60, 0xD6, 0x80, 0x25, 0xA9, 0x63, 0xBE, 0x03, 0x01, 0x4E, 0x38,
                0xE2, 0xF9, 0xA2, 0x34, 0xFF, 0xBB, 0x3E, 0x03, 0x44, 0x78, 0x00, 0x90, 0xCB, 0x88, 0x11, 0x3A, 0x94,
                0x65, 0xC0, 0x7C, 0x63, 0x87, 0xF0, 0x3C, 0xAF, 0xD6, 0x25, 0xE4, 0x8B, 0x38, 0x0A, 0xAC, 0x72, 0x21,
                0xD4, 0xF8, 0x07
        };
    };

    class Cartridge {
    public:
        using SaveType_t = std::pair<std::string, E_SaveType>;
        std::array<uint8_t, 0x10000> SRAM;

        Cartridge() = delete;

        Cartridge(const char *pathStr) {
            using namespace std::filesystem;
            path romPath(pathStr);
            if (exists(romPath)) {
                romData = LoadFileToBuffer(romPath);
                Header header = GetHeader() ;

                if (header.Verify()) {
                    _saveType = CheckSaveType() ;
                } // if
                else {
                    GGLOG("Rom verify failed, probably not a valid GBA rom file.") ;
                } // else
            } // if
            else {
                GGLOG("File does not exist!!") ;
                std::exit(-1) ;
            } // else
        }

        uint8_t* ImagePtr() {
            return romData.data() + EntrypointOffset() ;
        }

        unsigned Size() {
            return romData.size() ;
        } // size()

        E_SaveType SaveType() {
            return _saveType ;
        } // saveType()

        Header GetHeader() {
            return Header(romData.data());
        } // GetHeader()

        unsigned EntrypointOffset() {
            Header header = GetHeader() ;
            return (reinterpret_cast<const uint32_t &>(header.entryPoint[0]) & 0xffffff) + 8 ;
        } // Rom_EntrypointOffset()

        unsigned GetSRAM_MirrorMask() {
            return SRAM_MirrorMask ;
        } // GetSRAM_MirrorMask()

    private :
        std::vector<uint8_t> romData;
        E_SaveType _saveType = E_UNKNOWN ;
        unsigned SRAM_MirrorMask = 0x7fff;

        E_SaveType CheckSaveType() {
            const uint32_t entryPointOffset = EntrypointOffset();

            for (size_t idx = entryPointOffset; idx < romData.size(); ++idx) {
                for (const auto&[idStr, idEnum] : saveTypeID) {
                    bool boundaryCheck = idx + idStr.size() < romData.size();
                    if (boundaryCheck && std::equal(idStr.begin(), idStr.end(), romData.begin() + idx)) {
                        if (idEnum != E_SRAM)
                            SRAM_MirrorMask = 0xffff ;
                        return idEnum;
                    } // if
                } // for
            } // for

            return E_UNKNOWN;
        } // CheckSaveType()

        std::array<SaveType_t, 6> saveTypeID{
                SaveType_t("SRAM_V", E_SRAM),
                SaveType_t("SRAM_F_V", E_SRAM),
                SaveType_t("EEPROM_V", E_EEPROM),
                SaveType_t("FLASH_V", E_FLASH64K),
                SaveType_t("FLASH512_V", E_FLASH64K),
                SaveType_t("FLASH1M_V", E_FLASH128K)
        };
    };
}

#endif //GGTEST_CARTRIDGE_H

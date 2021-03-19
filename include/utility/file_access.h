//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <fstream>
#include <vector>

#ifndef GGADV_FILE_ACCESS_H
#define GGADV_FILE_ACCESS_H

namespace gg_core {
    std::vector<uint8_t> LoadFileToBuffer(const std::filesystem::path& filePath){;
        if (exists(filePath)) {
            std::ifstream stream(filePath.c_str(), std::ios::in | std::ios::binary);
            return std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        } // if
        else {
            // logger.LogWarning(fmt::format("File: \"{}\" doesn't exist!", filePath.string())) ;
            GGLOG("Load file error");
        } // else
    } // LoadFileToBuffer()
}

#endif //GGADV_FILE_ACCESS_H

//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <fstream>
#include <vector>

#ifndef GGADV_FILE_ACCESS_H
#define GGADV_FILE_ACCESS_H

namespace gg_core {
    static void LoadFileToBuffer(const std::filesystem::path& filePath, std::vector<uint8_t>& romBuffer){
        if (exists(filePath)) {
            std::ifstream stream(filePath.c_str(), std::ios::in | std::ios::binary);
            romBuffer = std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        } // if
        else {
            // logger.LogWarning(fmt::format("File: \"{}\" doesn't exist!", filePath.string())) ;
            spdlog::error("Load file error");
        } // else
    } // LoadFileToBuffer()
}

#endif //GGADV_FILE_ACCESS_H

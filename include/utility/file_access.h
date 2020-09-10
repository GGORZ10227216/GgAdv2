//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <fstream>
#include <vector>

#ifndef GGADV_FILE_ACCESS_H
#define GGADV_FILE_ACCESS_H

namespace gg_core {
    std::vector<char> LoadFileToBuffer(const std::filesystem::path& filePath){
        std::vector<char> result;

        if (exists(filePath)) {
            std::fstream fs(filePath.c_str(), std::fstream::in | std::fstream::binary) ;
            result.resize(file_size(filePath)) ;
            fs.read(result.data(), file_size(filePath)) ;
            fs.close() ;
        } // if
        else {
            // logger.LogWarning(fmt::format("File: \"{}\" doesn't exist!", filePath.string())) ;
        } // else

        return result ;
    } // LoadFileToBuffer()
}

#endif //GGADV_FILE_ACCESS_H

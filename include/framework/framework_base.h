//
// Created by orzgg on 2020-09-04.
//

#include <fstream>
#include <memory>
#include <filesystem>
#include <fmt/format.h>

#include <logger.h>

#ifndef GGADV_FRAMEWORK_BASE_H
#define GGADV_FRAMEWORK_BASE_H

namespace gg_core {
    template <typename T>
    class FrameworkBase {
    public :
        Logger logger ;

        std::vector<char> LoadFileToBuffer(const std::filesystem::path& filePath) {
            return static_cast<T*>(this)->LoadFileToBufferImpl(filePath) ;
        } // LoadFileToBuffer()

//        void Init() {
//            return static_cast<T*>(this)->InitImpl() ;
//        } // Init()
//
//        void Run() {
//            return static_cast<T*>(this)->RunImpl() ;
//        } // Tick()
//
//        void Close() {
//            return static_cast<T*>(this)->CloseImpl() ;
//        } // Close()

        std::vector<char> LoadFileToBufferImpl(const std::filesystem::path& filePath){
            std::vector<char> result;

            if (exists(filePath)) {
                std::fstream fs(filePath.c_str(), std::fstream::in | std::fstream::binary) ;
                result.resize(file_size(filePath)) ;
                fs.read(result.data(), file_size(filePath)) ;
                fs.close() ;
            } // if
            else {
                logger.LogWarning(fmt::format("File: \"{}\" doesn't exist!", filePath.string())) ;
            } // else

            return result ;
        } // LoadFileToBufferImpl()

    private :
        FrameworkBase() = default ;
        friend T ;
    };
}


#endif //GGADV_FRAMEWORK_BASE_H

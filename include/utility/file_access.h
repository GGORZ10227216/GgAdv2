//
// Created by orzgg on 2020-09-04.
//

#include <filesystem>
#include <fstream>
#include <vector>
#include <mem_enum.h>
#include <iostream>
#ifndef GGADV_FILE_ACCESS_H
#define GGADV_FILE_ACCESS_H

namespace gg_core {
static void LoadFileToBuffer(const std::filesystem::path &filePath, std::vector<uint8_t> &romBuffer) {
  if (exists(filePath)) {
	const unsigned romSize = file_size(filePath);
	if (romSize > gg_mem::MAX_GBA_ROMSIZE) {
	  std::cerr << "Not a valid rom file! Rom size is too large!" << std::endl;
	  std::exit(-1);
	} // if

	std::ifstream stream(filePath.c_str(), std::ios::in | std::ios::binary);
	stream.read(reinterpret_cast<char *>(romBuffer.data()), romSize);
  } // if
  else {
	std::cerr << "File does not exist!!" << std::endl;
	std::exit(-1);
	// logger.LogWarning(fmt::format("File: \"{}\" doesn't exist!", filePath.string())) ;
//	spdlog::error("Load file error");
  } // else
} // LoadFileToBuffer()
}

#endif //GGADV_FILE_ACCESS_H

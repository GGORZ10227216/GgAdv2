//
// Created by buildmachine on 2021-03-18.
//

#include <mem_enum.h>
#include <iostream>
#include <filesystem>
#include <save_memory.h>

#ifndef GGTEST_SRAM_H
#define GGTEST_SRAM_H

namespace gg_core::gg_mem {
struct SRAM : public SaveMemory {
  constexpr static unsigned SRAM_SIZE = 0x8000;

  SRAM(const std::filesystem::path& savePath, unsigned &c) :
	  SaveMemory(savePath, c)
  {
	_data.resize(SRAM_SIZE);
	std::fill(_data.begin(), _data.end(), 0xff);
  }

  virtual ~SRAM() = default;

  void Write(const uint32_t relativeAddr, const unsigned data) override {
	_data[relativeAddr] = data & 0xff;
  } // Write()

  unsigned Read(const uint32_t relativeAddr) override {
	return _data[relativeAddr];
  } // Read()

 private:
  std::vector<uint8_t> _data;

  void WriteSaveToFile() override {
	std::fstream saveFile(savePath_, std::ios::out | std::ios::binary);
	saveFile.write(reinterpret_cast<const char*>(_data.data()), SRAM_SIZE);
	saveFile.close();
  } // WriteSaveToFile()

  void ReadSaveFromFile() override {
	if (!std::filesystem::exists(savePath_)) {
	  std::cout << "SRAM save file not found, create one." << std::endl;
	  WriteSaveToFile();
	} // if
	else {
	  std::fstream saveFile(savePath_, std::ios::in | std::ios::binary);
	  saveFile.read(reinterpret_cast<char*>(_data.data()), SRAM_SIZE);
	  saveFile.close();
	} // else
  } // ReadSaveFromFile()
};
} // namespace gg_core::gg_mem
#endif //GGTEST_SRAM_H

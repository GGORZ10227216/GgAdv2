//
// Created by Orzgg on 11/27/2023.
//

#include <filesystem>
#include <fstream>
#include <string>
#include <filesystem>

#ifndef GGADV_INCLUDE_COMPONENT_SAVE_MEMORY_H_
#define GGADV_INCLUDE_COMPONENT_SAVE_MEMORY_H_

namespace gg_core::gg_mem {
class Cartidge;

struct SaveMemory {
  SaveMemory(const std::filesystem::path& savePath, unsigned &c) :
  	savePath_(savePath.string()), _mmuCycleCounterRef(c) {}
  virtual ~SaveMemory() = default;

  virtual void Write(uint32_t relativeAddr, unsigned data) = 0;
  virtual unsigned Read(uint32_t relativeAddr) = 0;

  virtual void WriteSaveToFile() = 0;
  virtual void ReadSaveFromFile() = 0;

  std::string savePath_;
  unsigned &_mmuCycleCounterRef;
};
}

#endif //GGADV_INCLUDE_COMPONENT_SAVE_MEMORY_H_

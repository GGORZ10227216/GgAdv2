//
// Created by orzgg on 2021-04-04.
//

#include <mem_enum.h>
#include <iostream>
#include <save_memory.h>

#ifndef GGTEST_EEPROM_HPP
#define GGTEST_EEPROM_HPP

namespace gg_core::gg_mem {
struct EEPROM : public SaveMemory {
  enum {EEPROM_512B_WIDTH = 6, EEPROM_8KB_WIDTH = 14};
  enum {EEPROM_READING = 0b11, EEPROM_WRITING = 0b10};
  enum {EEPROM_READY = 0b1};

  EEPROM(const std::filesystem::path& savePath, unsigned &c) :
	  SaveMemory(savePath, c)
  {
	// We are always treating EEPROM as 8KB EEPROM, even if it's possible to be 512B EEPROM.
	_data.resize(1024);
  }

  virtual ~EEPROM() = default;

  bool IsInitialized() const {
	return _initialized;
  } // IsInitialized()

  void Initialize(unsigned dma3cnt) {
	switch (dma3cnt) {
	case 9: case 73:
		_addrWidth = EEPROM_512B_WIDTH;
		break;
	case 17: case 81:
		_addrWidth = EEPROM_8KB_WIDTH;
		break;
	} // switch

	if (_addrWidth == 0) {
	  std::cerr << "Can not deduce EEPROM size, stop emulation now." << std::endl;
	  std::exit(-1);
	} // if

	_initialized = true;
  } // Initialize()

  void Write(const uint32_t relativeAddr, const unsigned data) override {
	uint8_t cmdBit = data & 0b1;
	switch (mode) {
	case LISTENING:
	  _accessMode = (_accessMode << 1) | cmdBit;

	  if (++_nthBit == 2) {
		mode = RECEIVING_ADDR;
		_nthBit = 0;
	  } // if
	  break;
	case RECEIVING_ADDR:
	  _addr = (_addr << 1) | cmdBit;
	  if (++_nthBit == _addrWidth) {
		// For 8KByte EEPROMs: a range of 0-3FFh, 14bit bus width
		// (only the lower 10 address bits are used, upper 4 bits should be zero)
		// Seems doing this on 512Byte EEPROM is also OK.
		_addr &= ~0b11110000000000;

		if (_accessMode == EEPROM_READING) {
		  // DMA controller is reading EEPROM, waiting for the end of transmission signal(an 0 bit)
		  mode = WAIT_CLOSE;
		  _nthBit = 0;
		} // if
		else {
		  // DMA controller is writing EEPROM, start to receive data
		  mode = RECEIVING_DATA;
		  _data[_addr] = 0;
		  _nthBit = 0;
		} // else
	  } // if
	  break;
	case RECEIVING_DATA:
	  _data[_addr] = (_data[_addr] << 1) | cmdBit;

	  if (++_nthBit == 64) {
		// This data bit is the final bit of writing data, waiting for the end of transmission signal(an 0 bit)
		mode = WAIT_CLOSE;
		_nthBit = 0;
	  } // if
	  break;
	case WAIT_CLOSE:
	  if (cmdBit != 0) {
		std::cerr << "Invalid EEPROM command: End of transmission signal is not equal to 0" << std::endl;
	  } // if
	  else {
		_ready = true;
		if (_accessMode == EEPROM_READING)
		  mode = TRANSMITTING;
		else {
		  // According to GBATEK, EEPROM needs 108368 cycles to complete a writing operation(which is, read + write).
		  _mmuCycleCounterRef += 108368;
		  WriteSaveToFile();
		  Reset();
		} // else
	  } // else
	  break;
	} // switch
  } // SendCmd()

  unsigned Read(const uint32_t relativeAddr) override {
	if (_ready && mode == TRANSMITTING) {
	  _nthBit += 1;
	  if (_nthBit >= 4 && _nthBit < 68) {
		uint16_t result = 0;
		result |= !!(_data[_addr] & (1 << _nthBit));

		// We should also reset the EEPROM state when transmission is done.
		if (_nthBit == 67)
			Reset();

		return result;
	  } // else
	} // if
	else {
	  // Emulating this behavior: [After the DMA, keep reading from the chip, by normal LDRH [DFFFF00h],
	  // until Bit 0 of the returned data becomes "1" (Ready)].
	  std::cerr << "System is reading EEPROM when transmission is not ready, this should be a busy waiting check" << std::endl;
	  return EEPROM_READY;
	} // else

	return 0;
  } // _ReadData()

private :
  unsigned _addrWidth = 0;

  enum E_WORK_MODE { LISTENING, RECEIVING_ADDR, RECEIVING_DATA, WAIT_CLOSE, TRANSMITTING };
  E_WORK_MODE mode = LISTENING;

  uint16_t _addr = 0;
  uint8_t _nthBit = 0, _accessMode = 0;
  bool _initialized = false, _ready = false;

  std::vector<uint64_t> _data;

  void Reset() {
	_addr = 0;
	_nthBit = 0;
	_accessMode = LISTENING;
  } // Reset()

  void WriteSaveToFile() override {
	std::fstream saveFile(savePath_, std::ios::out | std::ios::binary);
	saveFile.write(reinterpret_cast<const char*>(_data.data()), _data.size() * sizeof(uint64_t));
	saveFile.close();
  } // WriteSaveToFile()

  void ReadSaveFromFile() override {
	if (!std::filesystem::exists(savePath_)) {
	  std::cout << "EEPROM save file not found, create one." << std::endl;
	  WriteSaveToFile();
	} // if
	else {
	  std::fstream saveFile(savePath_, std::ios::in | std::ios::binary);
	  saveFile.read(reinterpret_cast<char*>(_data.data()), _data.size() * sizeof(uint64_t));
	  saveFile.close();
	} // else
  } // ReadSaveFromFile()
};
}

#endif //GGTEST_EEPROM_HPP

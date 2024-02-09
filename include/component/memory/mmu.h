//
// Created by orzgg on 2020-09-04.
//

#include <bit_manipulate.h>
#include <display_memory.h>
#include <cpu_enum.h>
#include <cpu_status.h>
#include <mmu_status.h>
#include <mirror.h>
#include <handler_table.h>

#include <functional>
#include <iostream>
#include <optional>
#include "io_enum.h"

#ifndef GGADV_MMU_H
#define GGADV_MMU_H

namespace gg_core {
class GbaInstance;

namespace gg_mem {
template<typename W>
inline unsigned CountAccessRotate(uint32_t addr) {
  if constexpr (SameSize<W, BYTE>())
	return 0;
  else if constexpr (SameSize<W, WORD>())
	return (addr & 0x1) << 3;
  else if constexpr (SameSize<W, DWORD>())
	return (addr & 0x3) << 3;
  else
	gg_core::Unreachable();
} // AddrAlign()

template <typename T>
inline const char* widthToString() {
  if constexpr (SameSize<T, BYTE>())
	return "BYTE";
  else if constexpr (SameSize<T, WORD>())
	return "WORD";
  else if constexpr (SameSize<T, DWORD>())
	return "DWORD";
  else
	gg_core::Unreachable();
} // widthToString()

class MMU : public MMU_Status {
public :
  MMU(GbaInstance &instance, const std::optional<std::filesystem::path> &romPath);

  inline int CalculateCycle(uint32_t absAddr, int accessWidth, E_AccessType accessType) const {
	// TODO: MMU request an I cycle, is it possible?
    if (accessType == E_AccessType::I_Cycle)
      return 1;
    else {
	  switch (accessWidth) {
		case 1:
		  return memCycleTable[accessType][absAddr >> 24].byte;
		case 2:
		  return memCycleTable[accessType][absAddr >> 24].word;
		case 4:
		  return memCycleTable[accessType][absAddr >> 24].dword;
	  }

	  return 0;
	} // else
  } // CalculateCycle()

  unsigned GetElapsedCycle() {
	const unsigned result = _elapsedCycle;
	_elapsedCycle = 0;
	return result;
  } // GetElapsedCycle()

  template<typename W, typename T>
  void Write(uint32_t absAddr, T value, E_AccessType accessType) requires std::is_same_v<W, T> {
	const auto accessWidth = static_cast<E_AccessWidth>(sizeof(W));

	unsigned addrTrait = (absAddr & 0xff000000) >> 24;
	requestAccessType = accessType;

	if (addrTrait > 0xf) {
	  // FIXME: Does invalid write consumed ONE cycle?
	  AddCycle(absAddr, I_Cycle, sizeof(W));
	  IllegalWrite<W>(absAddr, value);
	} // if
	else {
	  constexpr unsigned handlerIndex = sizeof(W) >> 1;
	  auto writeHandler = std::get<handlerIndex>(writeHandlerTable[addrTrait]);
	  AddCycle(absAddr, accessType, sizeof(W));
	  std::invoke(writeHandler, this, absAddr, value);
	} // else

	lastAccessAddr = absAddr;
	_cpuStatus.fetchAccessType = gg_mem::N_Cycle;
  } // Write()

  template<typename W>
  uint32_t Read(uint32_t absAddr, E_AccessType accessType) {
	const auto accessWidth = static_cast<E_AccessWidth>(sizeof(W));
	unsigned addrTrait = (absAddr & 0xff000000) >> 24;

	// Strange behavior of "Read WORD from unaligned address":
	// According to the NO$GBA's behavior, 16bit read still need
	// rotating. And address is aligned to 16bit bus.
	// But rotating result is affect to "whole 32bit register",
	// that means we need to fix the return type of Read() to 32bit

	uint32_t result = 0;
	requestAccessType = accessType;

	if (addrTrait > 0xf) {
	  AddCycle(absAddr, I_Cycle, sizeof(W));
	  result = IllegalRead<W>(absAddr);
	} // if
	else {
	  constexpr unsigned handlerIndex = sizeof(W) >> 1;
	  auto readHandler = std::get<handlerIndex>(readHandlerTable[addrTrait]);

	  AddCycle(absAddr, accessType, sizeof(W));
	  result = std::invoke(readHandler, this, absAddr);
	} // else

	lastAccessAddr = absAddr;
	if constexpr (sizeof(W) == 1)
	  return result;
	else {
	  const unsigned rotate = CountAccessRotate<W>(absAddr);
	  return rotr(result, rotate);
	} // else
  } // Read()

  void AddCycle(const uint32_t absAddr, const E_AccessType accessType, const unsigned accessWide, const char* comment = nullptr);
  void RegisterIOHandler(const std::vector<std::pair<gg_io::E_IO_OFFSET, IOWriteHandler>> &handlerList);

  GbaInstance &_instance;
 private:
  std::array<IOWriteHandler, E_RamSize::E_IO_SIZE> ioWriteHandlerTable;

  void FifoWrite(const unsigned channelIdx, const uint32_t data);

  template <typename T>
  uint32_t IllegalShift(uint32_t value, uint32_t absAddr) {
	// Just found that mgba has this wired behavior, not sure NO$GBA's.....
	constexpr unsigned memoryBusMask = sizeof(uint32_t) - sizeof(T);
	return (value >> ((absAddr & memoryBusMask) << 3)) & 0xffffffff;
  } // IllegalShift()

  template <typename T>
  T IllegalRead(uint32_t absAddr) {
	const uint32_t illegalReadValue = IllegalReadValue();
	std::cerr << "Illegal " << widthToString<T>() << " read from address 0x" << std::hex << absAddr << std::endl;

	return IllegalShift<T>(illegalReadValue, absAddr);
  } // IllegalRead()

  template <typename T>
  T BIOS_Read(uint32_t absAddr) {
	const uint32_t targetAddr = AlignAddr<T>(absAddr);

	if (targetAddr < E_RamSize::E_BIOS_SIZE) {
	  if (_cpuStatus._regs[gg_cpu::pc] < 0x4000) {
		// TODO: store last fetched instruction
		T result = reinterpret_cast<T&>(bios_data[targetAddr]);
		bios_readbuf = result;
		return result;
	  } // if
	  else
		return IllegalShift<T>(bios_readbuf, absAddr);
	} // if
	else
	  return IllegalRead<T>(absAddr);
  } // MMU::BIOS_Read()

  template <typename T>
  void IllegalWrite(uint32_t absAddr, T data) {
	std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to unused area 0x"
			  << std::hex << absAddr << std::endl;
  } // MMU::IllegalWrite()

  template <typename T>
  void BIOS_Write(uint32_t absAddr, T data) {
	std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to BIOS area 0x"
			  << std::hex << absAddr << std::endl;
  } // MMU::BIOS_Write()

  template <typename T>
  T EWRAM_Read(uint32_t absAddr) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_EWRAM_SIZE);
	return reinterpret_cast<T&>(EWRAM[relativeAddr]);
  } // MMU::EWRAM_Read()

  template <typename T>
  void EWRAM_Write(uint32_t absAddr, T data) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_EWRAM_SIZE);
	if (relativeAddr == 0x795c)
	  std::cout << std::endl;

	reinterpret_cast<T&>(EWRAM[relativeAddr]) = data;
  } // MMU::EWRAM_Write()

  template <typename T>
  T IWRAM_Read(uint32_t absAddr) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_IWRAM_SIZE);
	return reinterpret_cast<T&>(IWRAM[relativeAddr]);
  } // MMU::IWRAM_Read()

  template <typename T>
  void IWRAM_Write(uint32_t absAddr, T data) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_IWRAM_SIZE);
	reinterpret_cast<T&>(IWRAM[relativeAddr]) = data;
  } // MMU::IWRAM_Write()

  template <typename T>
  T IO_Read(uint32_t absAddr) {
	// According to GBATEK, [Reading from Unused or Write-Only I/O Ports] section:
	//     Works like above Unused Memory when the entire 32bit memory fragment is Unused (eg. 0E0h)
	//     and/or Write-Only (eg. DMA0SAD). And otherwise, returns zero if the lower 16bit fragment is
	//     readable (eg. 04Ch=MOSAIC, 04Eh=NOTUSED/ZERO).
	// So we can not use handler table technique to handle IO read.

	using namespace gg_io;
	const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart);
	const T allReadableMask = static_cast<T>(0x01010101) * static_cast<unsigned>(E_IO_AccessMode::R);
	T policy = *((T*)(policyTable.data() + relativeAddr));

	if ((policy & allReadableMask) == 0x0) {
	  // Whole target IO region are write only or unused
	  return IllegalRead<T>(absAddr);
	} // if
	else {
	  // Partially readable, just return 0
	  io_reg32_t result = 0;
	  for (int i = 0 ; i < sizeof(T) ; ++i) {
		if (policyTable[relativeAddr + i] != static_cast<unsigned>(E_IO_AccessMode::W))
		  result.bytes[i] = IOReg[relativeAddr + i];
		else
		  result.bytes[i] = 0;
	  } // for

	  return result.dword;
	} // else
  } // MMU::IO_Read()

  template <typename T>
  void IO_Write(uint32_t absAddr, T data) {
	using namespace gg_io;

	const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart);
	const io_reg32_t data_ = data;

	// dma sound fifo only allow 32bit write
	if constexpr (sizeof(T) == 4) {
	  if (absAddr == ADDR_FIFO_A || absAddr == ADDR_FIFO_B)
	  	FifoWrite((absAddr - ADDR_FIFO_A) / 4, data);
	} // if constexpr

	for (int i = 0 ; i < sizeof(T) ; ++i) {
	  // Stop writing if relativeAddr exceeds I/O register's area(0x0400'0000 ~ 0x0400'03FE)
	  // Just don't handle the undocumented I/O registers for now.
	  const uint32_t chkCur = (relativeAddr + i) & ~0x1;
	  const bool addrIsReadonly =
		  chkCur == OFFSET_VCOUNT || chkCur == OFFSET_KEYINPUT || chkCur == OFFSET_JOYSTAT;

	  if (addrIsReadonly || relativeAddr + i >= ioWriteHandlerTable.size())
		break;

	  ioWriteHandlerTable[relativeAddr + i](_instance, relativeAddr + i, data_.bytes[i]);
	} // for
  } // IO_Read()

  template <typename T>
  T Palette_Read(uint32_t absAddr) {
	// todo: Plus 1 cycle if GBA accesses video memory at the same time.
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_PALETTE_SIZE);
	return reinterpret_cast<T&>(videoRAM.palette_data[relativeAddr]);
  } // MMU::Palette_Read()

  template <typename T>
  void Palette_Write(uint32_t absAddr, T data) {
	// todo: Plus 1 cycle if GBA accesses video memory at the same time.
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_PALETTE_SIZE);
	reinterpret_cast<T&>(videoRAM.palette_data[relativeAddr]) = data;
  } // MMU::Palette_Write()

  template <typename T>
  T VRAM_Read(uint32_t absAddr) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_VRAM_SIZE);
	return reinterpret_cast<T&>(videoRAM.vram_data[relativeAddr]);
  } // MMU::VRAM_Read()

  template <typename T>
  void VRAM_Write(uint32_t absAddr, T data) {
	const uint32_t relativeAddr = VRAM_MIRROR(AlignAddr<T>(absAddr));
	reinterpret_cast<T&>(videoRAM.vram_data[relativeAddr]) = data;
  } // MMU::VRAM_Write()

  template <typename T>
  T OAM_Read(uint32_t absAddr) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_OAM_SIZE);
	return reinterpret_cast<T&>(videoRAM.oam_data[relativeAddr]);
  } // MMU::OAM_Read()

  template <typename T>
  void OAM_Write(uint32_t absAddr, T data) {
	const uint32_t relativeAddr = NORMAL_MIRROR(AlignAddr<T>(absAddr), E_OAM_SIZE);
	reinterpret_cast<T&>(videoRAM.oam_data[relativeAddr]) = data;
  } // MMU::OAM_Write()

  // TODO: implement this
  template <typename T>
  T GAMEPAK_WS0Read(uint32_t absAddr) {
	const uint32_t relativeAddr = Cartridge::RelativeAddr<E_WS0>(AlignAddr<T>(absAddr));
	return reinterpret_cast<T&>(cartridge.romData[relativeAddr]);
  } // MMU::GAMEPAK_WS0Read()

  template <typename T>
  void GAMEPAK_WS0Write(uint32_t absAddr, T data) {
	std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to GAMEPAK_WS0 area 0x"
			  << std::hex << absAddr << std::endl;
  } // MMU::GAMEPAK_WS0Write()

  template <typename T>
  T GAMEPAK_WS1Read(uint32_t absAddr) {
	const uint32_t relativeAddr = Cartridge::RelativeAddr<E_WS1>(AlignAddr<T>(absAddr));
	return reinterpret_cast<T&>(cartridge.romData[relativeAddr]);
  } // MMU::GAMEPAK_WS1Read()

  template <typename T> void GAMEPAK_WS1Write(uint32_t absAddr, T data) {
	std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to GAMEPAK_WS1 area 0x"
			  << std::hex << absAddr << std::endl;
  } // MMU::GAMEPAK_WS1Write()

  template <typename T>
  T GAMEPAK_WS2Read(uint32_t absAddr) {
	const uint32_t relativeAddr = Cartridge::RelativeAddr<E_WS2>(AlignAddr<T>(absAddr));
	const bool isEEPROM_Access = cartridge.SaveType() == E_EEPROM && cartridge.IsEEPROM_Access(absAddr);

	if (isEEPROM_Access) {
	  if constexpr (sizeof(T) != 2) {
		// Byte & DWORD access to EEPROM is impossible?
		std::cerr << "System attempt to read " << widthToString<T>() << " value from EEPROM area 0x"
				  << std::hex << absAddr << std::endl;
		return EEPROM::EEPROM_READY;
	  } // if constexpr
	  else {
		auto* eeprom = (EEPROM*)cartridge._saveMem.get();
		if (!eeprom->IsInitialized()) {
		  // We are guessing the EEPROM size by DMA3CNT_L's value when the first write happens.
		  // If dma3cnt is 17, then the EEPROM size is 8192 bytes.

		  const uint16_t dma3cnt = IOReg[gg_io::OFFSET_DMA3CNT_L];
		  eeprom->Initialize(dma3cnt);
		} // if

		return eeprom->Read(relativeAddr);
	  } // else
	} // if

	return reinterpret_cast<T&>(cartridge.romData[relativeAddr]);
  } // MMU::GAMEPAK_WS2Read()

  template <typename T> void GAMEPAK_WS2Write(uint32_t absAddr, T data) {
	const uint32_t relativeAddr = Cartridge::RelativeAddr<E_WS2>(AlignAddr<T>(absAddr));
	const bool isEEPROM_Access = cartridge.SaveType() == E_EEPROM && cartridge.IsEEPROM_Access(absAddr);

	if (isEEPROM_Access) {
	  if constexpr (sizeof(T) != 2) {
		std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to EEPROM area 0x"
				  << std::hex << absAddr << std::endl;
	  } // if constexpr
	  else {
		auto* eeprom = (EEPROM*)cartridge._saveMem.get();
		if (!eeprom->IsInitialized()) {
		  // We are guessing the EEPROM size by DMA3CNT_L's value when the first write happens.
		  // If dma3cnt is 81, then the EEPROM size is 8192 bytes.

		  const uint16_t dma3cnt = IOReg[gg_io::OFFSET_DMA3CNT_L];
		  eeprom->Initialize(dma3cnt);
		} // if

		eeprom->Write(relativeAddr, data);
	  } // else

	  return;
	} // if

	std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to GAMEPAK_WS2 area 0x"
			  << std::hex << absAddr << std::endl;
  } // MMU::GAMEPAK_WS2Write()

  template <typename T>
  T SRAM_Read(uint32_t absAddr) {
	if constexpr (sizeof(T) != sizeof(BYTE)) {
	  std::cerr << "System attempt to read " << widthToString<T>() << " value from SRAM area 0x"
				<< std::hex << absAddr << std::endl;
	  return 0;
	} // if constexpr
	else {
	  const uint32_t relativeAddr = (absAddr - SRAM_Start) & (SRAM::SRAM_SIZE - 1);
	  return cartridge._saveMem->Read(relativeAddr);;
	} // else
  } // MMU::SRAM_Read()

  template <typename T>
  void SRAM_Write(uint32_t absAddr, T data) {
	if constexpr (sizeof(T) != sizeof(BYTE)) {
	  std::cerr << "System attempt to write " << widthToString<T>() << " value [" << data << "] to SRAM area 0x"
				<< std::hex << absAddr << std::endl;
	} // if constexpr
	else {
	  const uint32_t relativeAddr = (absAddr - SRAM_Start) & (SRAM::SRAM_SIZE - 1);
	  cartridge._saveMem->Write(relativeAddr, data);
	} // else
  } // MMU::SRAM_Write()

  constexpr static std::array<MMUReadHandler, 16> readHandlerTable {
	  std::make_tuple(&MMU::BIOS_Read<uint8_t>, &MMU::BIOS_Read<uint16_t>, &MMU::BIOS_Read<uint32_t>),
	  std::make_tuple(&MMU::IllegalRead<uint8_t>, &MMU::IllegalRead<uint16_t>, &MMU::IllegalRead<uint32_t>),
	  std::make_tuple(&MMU::EWRAM_Read<uint8_t>, &MMU::EWRAM_Read<uint16_t>, &MMU::EWRAM_Read<uint32_t>),
	  std::make_tuple(&MMU::IWRAM_Read<uint8_t>, &MMU::IWRAM_Read<uint16_t>, &MMU::IWRAM_Read<uint32_t>),
	  std::make_tuple(&MMU::IO_Read<uint8_t>, &MMU::IO_Read<uint16_t>, &MMU::IO_Read<uint32_t>),
	  std::make_tuple(&MMU::Palette_Read<uint8_t>, &MMU::Palette_Read<uint16_t>, &MMU::Palette_Read<uint32_t>),
	  std::make_tuple(&MMU::VRAM_Read<uint8_t>, &MMU::VRAM_Read<uint16_t>, &MMU::VRAM_Read<uint32_t>),
	  std::make_tuple(&MMU::OAM_Read<uint8_t>, &MMU::OAM_Read<uint16_t>, &MMU::OAM_Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS0Read<uint8_t>, &MMU::GAMEPAK_WS0Read<uint16_t>, &MMU::GAMEPAK_WS0Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS0Read<uint8_t>, &MMU::GAMEPAK_WS0Read<uint16_t>, &MMU::GAMEPAK_WS0Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS1Read<uint8_t>, &MMU::GAMEPAK_WS1Read<uint16_t>, &MMU::GAMEPAK_WS1Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS1Read<uint8_t>, &MMU::GAMEPAK_WS1Read<uint16_t>, &MMU::GAMEPAK_WS1Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS2Read<uint8_t>, &MMU::GAMEPAK_WS2Read<uint16_t>, &MMU::GAMEPAK_WS2Read<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS2Read<uint8_t>, &MMU::GAMEPAK_WS2Read<uint16_t>, &MMU::GAMEPAK_WS2Read<uint32_t>),
	  std::make_tuple(&MMU::SRAM_Read<uint8_t>, &MMU::SRAM_Read<uint16_t>, &MMU::SRAM_Read<uint32_t>),
	  std::make_tuple(&MMU::SRAM_Read<uint8_t>, &MMU::SRAM_Read<uint16_t>, &MMU::SRAM_Read<uint32_t>)
  };

  constexpr static std::array<MMUWriteHandler, 16> writeHandlerTable = {
	  std::make_tuple(&MMU::BIOS_Write<uint8_t>, &MMU::BIOS_Write<uint16_t>, &MMU::BIOS_Write<uint32_t>),
	  std::make_tuple(&MMU::IllegalWrite<uint8_t>, &MMU::IllegalWrite<uint16_t>, &MMU::IllegalWrite<uint32_t>),
	  std::make_tuple(&MMU::EWRAM_Write<uint8_t>, &MMU::EWRAM_Write<uint16_t>, &MMU::EWRAM_Write<uint32_t>),
	  std::make_tuple(&MMU::IWRAM_Write<uint8_t>, &MMU::IWRAM_Write<uint16_t>, &MMU::IWRAM_Write<uint32_t>),
	  std::make_tuple(&MMU::IO_Write<uint8_t>, &MMU::IO_Write<uint16_t>, &MMU::IO_Write<uint32_t>),
	  std::make_tuple(&MMU::Palette_Write<uint8_t>, &MMU::Palette_Write<uint16_t>, &MMU::Palette_Write<uint32_t>),
	  std::make_tuple(&MMU::VRAM_Write<uint8_t>, &MMU::VRAM_Write<uint16_t>, &MMU::VRAM_Write<uint32_t>),
	  std::make_tuple(&MMU::OAM_Write<uint8_t>, &MMU::OAM_Write<uint16_t>, &MMU::OAM_Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS0Write<uint8_t>, &MMU::GAMEPAK_WS0Write<uint16_t>, &MMU::GAMEPAK_WS0Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS0Write<uint8_t>, &MMU::GAMEPAK_WS0Write<uint16_t>, &MMU::GAMEPAK_WS0Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS1Write<uint8_t>, &MMU::GAMEPAK_WS1Write<uint16_t>, &MMU::GAMEPAK_WS1Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS1Write<uint8_t>, &MMU::GAMEPAK_WS1Write<uint16_t>, &MMU::GAMEPAK_WS1Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS2Write<uint8_t>, &MMU::GAMEPAK_WS2Write<uint16_t>, &MMU::GAMEPAK_WS2Write<uint32_t>),
	  std::make_tuple(&MMU::GAMEPAK_WS2Write<uint8_t>, &MMU::GAMEPAK_WS2Write<uint16_t>, &MMU::GAMEPAK_WS2Write<uint32_t>),
	  std::make_tuple(&MMU::SRAM_Write<uint8_t>, &MMU::SRAM_Write<uint16_t>, &MMU::SRAM_Write<uint32_t>),
	  std::make_tuple(&MMU::SRAM_Write<uint8_t>, &MMU::SRAM_Write<uint16_t>, &MMU::SRAM_Write<uint32_t>)
  };
};

}
}

#endif //GGADV_MMU_H

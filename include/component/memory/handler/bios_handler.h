//
// Created by buildmachine on 2021-03-16.
//


#include <mem_enum.h>
#include <gg_utility.h>

#ifndef GGTEST_BIOS_HANDLER_H
#define GGTEST_BIOS_HANDLER_H

namespace gg_core::gg_mem {
template<typename T>
T IllegalShift(uint32_t value, uint32_t absAddr) {
  // Just found that mgba has this wired behavior, not sure NO$GBA's.....
  const unsigned memoryBusMask = sizeof(uint32_t) - sizeof(T);
  return (value >> ((absAddr & memoryBusMask) << 3)) & static_cast<T>(0xffffffff);
} // IllegalShift()

template<typename T>
T NoUsed_Read(GbaInstance &instance, uint32_t absAddr) {
//  instance.mmu.logger->warn(
//	  "Attempt to READ {} from address 0x{:x}",
//	  accessWidthName[sizeof(T) >> 1],
//	  absAddr
//  );

  return IllegalShift<T>(instance.mmu.IllegalReadValue(), absAddr);
} // NoUsed_Read()

template<typename T>
T NoUsed_IORead(GbaInstance &instance, uint32_t absAddr) {
//  instance.mmu.logger->warn(
//	  "Attempt to READ {} from address 0x{:x}",
//	  accessWidthName[sizeof(T) >> 1],
//	  absAddr
//  );

  // FIXME: eggvance is using pre byte reading for IO access, not sure
  //        this is correct or not......

  uint32_t result = 0;
  for (int i = 0; i < sizeof(T); ++i) {
	result |= static_cast<uint8_t>(instance.mmu.IllegalReadValue()) << 8 * i;
  } // for

  return result;
} // NoUsed_IORead()

template<typename T>
void NoUsed_Write(GbaInstance &instance, uint32_t absAddr, T data) {
//  instance.mmu.logger->warn(
//	  "Attempt to WRITE {} value (0x{:x}) to unused area(0x{:x})",
//	  accessWidthName[sizeof(T) >> 1],
//	  data,
//	  absAddr
//  );
} // NoUsed_Write()

template<typename T>
T BIOS_Read(GbaInstance &instance, uint32_t absAddr) {
  const uint32_t targetAddr = AlignAddr<T>(absAddr);

  if (targetAddr < E_RamSize::E_BIOS_SIZE) {
	if (instance.cpu._regs[gg_cpu::pc] <= 0x3fff) {
	  if constexpr (sizeof(T) == sizeof(uint32_t))
		instance.mmu.bios_readbuf =
			reinterpret_cast<uint32_t &>(instance.mmu.bios_data[targetAddr]); // only fetched opcode will affect read buffer
	  return reinterpret_cast<T &>(instance.mmu.bios_data[targetAddr]);
	} // if
	else
	  return IllegalShift<T>(instance.mmu.bios_readbuf, absAddr);
  } // if
  else
	return NoUsed_Read<T>(instance, absAddr);
} // BIOS_Read()

template<typename T>
void BIOS_Write(GbaInstance &instance, uint32_t absAddr, T data) {
//  instance.mmu.logger->warn(
//	  "Attempt to WRITE {} value ({}) to BIOS area({})",
//	  accessWidthName[sizeof(T) >> 1],
//	  data,
//	  absAddr
//  );
}
}

#endif //GGTEST_BIOS_HANDLER_H

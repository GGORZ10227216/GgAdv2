//
// Created by buildmachine on 2021-03-16.
//


#include <mem_enum.h>
#include <gg_utility.h>

#include <io_enum.h>

#ifndef GGTEST_IO_HANDLER_H
#define GGTEST_IO_HANDLER_H

namespace gg_core::gg_mem {
template<typename T>
T IO_Read(GbaInstance &instance, uint32_t absAddr) {
  // 04000000-040003FE   I/O Registers
  using namespace gg_io;

  const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart);
  uint32_t result = 0;
  if (relativeAddr < E_RamSize::E_IO_SIZE) {
	for (int i = 0; i < sizeof(T); ++i) {
	  const auto curPolicy = static_cast<E_IO_AccessMode> (policyTable[relativeAddr + i]);
	  result <<= 8;
	  if (curPolicy == E_IO_AccessMode::R || curPolicy == E_IO_AccessMode::RW)
		result |= instance.mmu.IOReg[relativeAddr + i];
	  else {
		if (i == 0)
		  return instance.mmu.IllegalReadValue();
		else {
		  /*Do nothing, let the high 16bit value to be zero*/
		} // else
	  } // else
	} // for

	return static_cast<T>(result);
  } // if
  else {
	// 04000400-04FFFFFF Not used
	return NoUsed_IORead<T>(instance, absAddr);;
  } // else
} // IO_Read()

template<typename T>
void IO_Write(GbaInstance &instance, uint32_t absAddr, T data) {
  // 04000000-040003FE   I/O Registers
  using namespace gg_io;

  const uint32_t relativeAddr = AlignAddr<T>(absAddr - ioStart);
  if (relativeAddr < E_RamSize::E_IO_SIZE) {
	const auto curPolicy = static_cast<E_IO_AccessMode> (policyTable[relativeAddr]);
	if (curPolicy == E_IO_AccessMode::W || curPolicy == E_IO_AccessMode::RW) {
	  // Just write the data directly, since we are reading IO by byte access(check policy per byte)
	  // so direct write is safe.
	  reinterpret_cast<T &>(instance.mmu.IOReg[relativeAddr]) = data;
	  // handle io behavior which relative with mmu directly.
	  switch (relativeAddr) {
	  case 0x200:
	  case 0x202:
	  case 0x208:
		/* IE & IF & IME */
		if (relativeAddr == 0x202)
		  reinterpret_cast<T &>(instance.mmu.IOReg[relativeAddr]) &= ~data; // special behavior of IF
		else
		  reinterpret_cast<T &>(instance.mmu.IOReg[relativeAddr]) = data;

		instance.cpu.CPU_StateChange();
		break;
	  case 0x204:
		/* WAITCNT */
		reinterpret_cast<T &>(instance.mmu.IOReg[relativeAddr]) = data;
		instance.mmu.UpdateWaitState();
		break;
	  } // switch

	  return;
	} // if
	else {
//	  instance.mmu.logger->warn(
//		  "Attempt to WRITE {} value to READ-ONLY IO register 0x{:x}",
//		  accessWidthName[sizeof(T) >> 1],
//		  absAddr
//	  );
	} // else
  } // if

  NoUsed_Write(instance, absAddr, data);
} // IO_Write()
}

#endif //GGTEST_IO_HANDLER_H

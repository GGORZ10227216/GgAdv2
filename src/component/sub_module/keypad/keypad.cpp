//
// Created by Orzgg on 1/7/2024.
//

#include <keypad/keypad.h>
#include <gba_instance.h>
#include <io_enum.h>

namespace gg_core {
using namespace gg_io;

Keypad::Keypad(GbaInstance &instance) :
	KEYINPUT((uint16_t&)instance.mmu.IOReg[OFFSET_KEYINPUT]),
	KEYCNT((uint16_t&)instance.mmu.IOReg[OFFSET_KEYCNT])
{
} // Keypad()

} // namespace gg_core
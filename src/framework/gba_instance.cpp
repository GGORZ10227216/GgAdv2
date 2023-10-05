//
// Created by orzgg on 2020-09-04.
//

#include <gba_instance.h>
#include <io_enum.h>

namespace gg_core {
GbaInstance::GbaInstance(const char *romPath) :
	cycleCounter(0),
	mmu(*this, romPath),
	cpu(*this),
	ppu(mmu.IOReg.data(),
		mmu.videoRAM.palette_data.data(),
		mmu.videoRAM.vram_data.data(),
		mmu.videoRAM.oam_data.data()
	),
	IF((uint16_t&)mmu.IOReg[gg_io::OFFSET_IF]),
	IE((uint16_t&)mmu.IOReg[gg_io::OFFSET_IE]),
	IME((uint16_t&)mmu.IOReg[gg_io::OFFSET_IME])
//	timer(*this),
//	dmaController(*this)
{
}

GbaInstance::GbaInstance() :
	mmu(*this, std::nullopt),
	cpu(*this),
	ppu(mmu.IOReg.data(),
		mmu.videoRAM.palette_data.data(),
		mmu.videoRAM.vram_data.data(),
		mmu.videoRAM.oam_data.data()
	),
	IF((uint16_t&)mmu.IOReg[gg_io::OFFSET_IF]),
	IE((uint16_t&)mmu.IOReg[gg_io::OFFSET_IE]),
	IME((uint16_t&)mmu.IOReg[gg_io::OFFSET_IME])
//	timer(*this),
//	dmaController(*this)
{
}
}

//
// Created by orzgg on 2020-09-04.
//

#include <gba_instance.h>

namespace gg_core {
GbaInstance::GbaInstance(const char *romPath) :
	cycleCounter(0),
	mmu(*this, romPath),
	cpu(*this),
	ppu(mmu.IOReg.data(),
		mmu.videoRAM.palette_data.data(),
		mmu.videoRAM.vram_data.data(),
		mmu.videoRAM.oam_data.data()
	)
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
	)
//	timer(*this),
//	dmaController(*this)
{
}
}

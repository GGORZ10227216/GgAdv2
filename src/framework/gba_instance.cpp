//
// Created by orzgg on 2020-09-04.
//

#include <gba_instance.h>

namespace gg_core {
GbaInstance::GbaInstance(const char *romPath) :
	oss(),
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
	oss(),
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

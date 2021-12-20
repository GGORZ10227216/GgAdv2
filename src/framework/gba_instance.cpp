//
// Created by orzgg on 2020-09-04.
//

#include <gba_instance.h>

namespace gg_core {
    GbaInstance::GbaInstance(const char* romPath) :
            oss(),
            logSink(std::make_shared<LOG>()),
            mmu(*this, romPath),
            cpu(*this, logSink),
            timer(*this),
            runner(_systemClk)
    {
    }

    GbaInstance::GbaInstance() :
            oss(),
            logSink(std::make_shared<LOG>()),
            mmu(*this, std::nullopt),
            cpu(*this, logSink),
            timer(*this),
            runner(_systemClk)
    {
    }
}

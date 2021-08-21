#include <iostream>
#include <optional>
#include <emu_framework.h>


using namespace gg_core::gg_cpu;

int main() {
    gg_core::GbaInstance gbaInstance("./testRom.gba");
    gg_core::gg_cpu::CPU& cpu = gbaInstance.cpu ;
    ArmAssembler armAsm(ASMMODE::ARM) ;
    ArmAssembler thumbAsm(ASMMODE::THUMB) ;

    while (true) {
        cpu.CPU_DebugTick() ;
    } // while

    return 0;
}

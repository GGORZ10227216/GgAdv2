#include <iostream>
#include <optional>
#include <emu_framework.h>

int main() {
    gg_core::gg_mem::MMU mmu(std::nullopt);
    gg_core::gg_cpu::CPU emu(mmu) ;
    return 0;
}

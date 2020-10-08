#include <iostream>
#include <optional>
#include <emu_framework.h>

int main() {
    for (int i = 0 ; i < 4096 ; ++i)
        gg_core::GbaInstance emu(std::nullopt) ;
    return 0;
}

//
// Created by buildmachine on 2020-12-22.
//

#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu;

    TEST_F(ggTest, swp_test) {
        using namespace gg_core;

        Arm egg;
        GbaInstance instance(std::nullopt);
        ArmAssembler gg_asm;

        unsigned int t = 0 ;
        TestField targetRd(0, 0xe, 1) ;
        TestField targetRn(0, 0xe, 1) ;
        TestField RnValue(0x3000000, 0x3007fff, 1) ;
        TestField targetRs(0, 0xe, 1) ;

        

    }
}
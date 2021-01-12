//
// Created by buildmachine on 2021-01-11.
//

#include <gg_test.h>

namespace {
    using namespace gg_core;
    using namespace gg_core::gg_cpu;
    using namespace gg_core::gg_mem;

    uint32_t baseAddr = 0x02020000 ;

    TEST_F(ggTest, ldrh_reg_offset) {
        TestField targetRd(0, 0xf, 1) ;
        TestField targetRn(0, 0xf, 1) ;
        TestField targetRm(0, 0xe, 1) ;

        TestField RmValue(0, 0x1ffff, 4) ;
    }
}
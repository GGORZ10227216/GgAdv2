//
// Created by orzgg on 2021-05-18.
//

#include <gg_test.h>

namespace {
    using namespace gg_core::gg_cpu ;

    TEST_F(ggTest, arm_unaligned_halfaccess_at_unused_test) {
        uint32_t instruction = 0xe1d100b0 ;
        const uint32_t answers[4] = {
            0x0000c301,
            0x010000c3,
            0x0000e3a0,
            0xa00000e3
        };

        for (int i = 0 ; i < 4 ; ++i) {
            instance._regs[ r1 ] = 0xfffffffc + i ;
            instance.fetchedBuffer[ 1 ] = 0xe3a0c301 ;

            instance._regs[ pc ] = 0x68;
            instance.RefillPipeline(&instance, gg_core::gg_mem::S_Cycle, gg_core::gg_mem::S_Cycle) ;

            instance.CPU_Test(instruction); // ldrh r0, [r1]

            ASSERT_TRUE(instance._regs[ 0 ] == answers[i] ) << std::hex
                                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                                            << "mine: " << instance._regs[ 0 ] << '\n'
                                                            << "answer: " << answers[i] << '\n' ;
        } // for
    }

    TEST_F(ggTest, arm_unaligned_byteaccess_at_unused_test) {
        uint32_t instruction = 0xe5d10000 ;
        const uint32_t answers[4] = {
                0x00000001,
                0x000000c3,
                0x000000a0,
                0x000000e3
        };

        for (int i = 0 ; i < 4 ; ++i) {
            instance._regs[ r1 ] = 0xfffffffc + i ;
            instance.fetchedBuffer[ 1 ] = 0xe3a0c301 ;

            instance._regs[ pc ] = 0x68;
            instance.RefillPipeline(&instance, gg_core::gg_mem::S_Cycle, gg_core::gg_mem::S_Cycle) ;

            instance.CPU_Test(instruction); // ldrb r0, [r1]

            ASSERT_TRUE(instance._regs[ 0 ] == answers[i] ) << std::hex
                                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                                            << "mine: " << instance._regs[ 0 ] << '\n'
                                                            << "answer: " << answers[i] << '\n' ;
        } // for
    }

    TEST_F(ggTest, arm_unaligned_signed_halfaccess_at_unused_test) {
        uint32_t instruction = 0xe1d100f0 ;
        const uint32_t answers[4] = {
                0xffffc301,
                0xffffffc3,
                0xffffe3a0,
                0xffffffe3
        };

        for (int i = 0 ; i < 4 ; ++i) {
            instance._regs[ r1 ] = 0xfffffffc + i ;
            instance.fetchedBuffer[ 1 ] = 0xe3a0c301 ;

            instance._regs[ pc ] = 0x68;
            instance.RefillPipeline(&instance, gg_core::gg_mem::S_Cycle, gg_core::gg_mem::S_Cycle) ;

            instance.CPU_Test(instruction); // ldrsh r0, [r1]

            ASSERT_TRUE(instance._regs[ 0 ] == answers[i] ) << std::hex
                                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                                            << "mine: " << instance._regs[ 0 ] << '\n'
                                                            << "answer: " << answers[i] << '\n' ;
        } // for
    }

    TEST_F(ggTest, arm_unaligned_signed_byteaccess_at_unused_test) {
        uint32_t instruction = 0xe1d100d0 ;
        const uint32_t answers[4] = {
                0x00000001,
                0xffffffc3,
                0xffffffa0,
                0xffffffe3
        };

        for (int i = 0 ; i < 4 ; ++i) {
            instance._regs[ r1 ] = 0xfffffffc + i ;
            instance.fetchedBuffer[ 1 ] = 0xe3a0c301 ;

            instance._regs[ pc ] = 0x68;
            instance.RefillPipeline(&instance, gg_core::gg_mem::S_Cycle, gg_core::gg_mem::S_Cycle) ;

            instance.CPU_Test(instruction); // ldrsb r0, [r1]

            ASSERT_TRUE(instance._regs[ 0 ] == answers[i] ) << std::hex
                                                            << gg_asm.DASM(instruction) << "[" << instruction << "]" << '\n'
                                                            << "mine: " << instance._regs[ 0 ] << '\n'
                                                            << "answer: " << answers[i] << '\n' ;
        } // for
    }
}
cmake_minimum_required(VERSION 3.17)
project(ggAdv)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g ")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -flto")

set(header_core
        include/instruction_class.h
        include/framework/logger.h
        include/component/cpu/cpu.h
        include/component/cpu/status.h
        include/component/component_class.h
        include/component/cpu/cpu_enum.h
        include/framework/emu_framework.h
        include/framework/framework_base.h
        src/framework/framework_base.cpp
        include/framework/gba_instance.h
        include/component/memory/mmu.h
        include/component/io/io.h
        include/gba_bios.h
        include/utility/file_access.h
        include/component/memory/memory_region.h
        include/component/memory/mem_enum.h
        include/component/memory/general_memory.h
        include/component/memory/display_memory.h
        include/component/memory/gamepak_memory.h
        include/utility/bit_manipulate.h)

set(header_arm_implement
        include/instruction/arm/arm_prototype.h
        include/instruction/arm/arm_instruction_table.h
        include/instruction/arm/v4_alu_implement.h
        include/instruction/arm/v4_branch_implement.h
        include/instruction/arm/v4_btransfer_implement.h
        include/instruction/arm/v4_interrupt_implement.h
        include/instruction/arm/v4_mul_implement.h
        include/instruction/arm/v4_mull_implement.h
        include/instruction/arm/v4_psr_implement.h
        include/instruction/arm/v4_swp_implement.h
        include/instruction/arm/v4_transfer_implement.h
        )

set(src_core
        src/framework/logger/console_logger.cpp
        src/cpu/cpu.cpp src/cpu/status.cpp)

add_executable(ggAdv main.cpp ${header_core} ${header_arm_implement} ${src_core})
    target_include_directories(ggAdv PUBLIC
            include
            include/component/
            include/component/cpu
            include/component/memory
            include/component/io
            include/framework
            include/instruction/arm
            include/utility
            )

    target_link_libraries(ggAdv /usr/local/lib/libfmt.a)
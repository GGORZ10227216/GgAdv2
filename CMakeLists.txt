cmake_minimum_required(VERSION 3.16)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKXX_FLAGS} -pthread -D_REENTRANT -I/usr/include/SDL2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")

project(ggAdv)
#    set(v4_arm_core_path include/component/cpu/core/arm)
#    set(v4_arm_decoder_src
#        ${v4_arm_core_path}/arm_decoder.h
#        ${v4_arm_core_path}/decoder/branch.h
#        ${v4_arm_core_path}/decoder/data_processing.h
#        ${v4_arm_core_path}/decoder/memory_access.h
#        ${v4_arm_core_path}/decoder/multiply.h
#        ${v4_arm_core_path}/decoder/psr_transfer.h
#        ${v4_arm_core_path}/decoder/software_interrupt.h
#    )
#    set(v4_arm_implement_src
#        ${v4_arm_core_path}/implements/v4_operand2.h
#        ${v4_arm_core_path}/implements/v4_alu_implement.h
#        ${v4_arm_core_path}/implements/v4_branch_implement.h
#        ${v4_arm_core_path}/implements/v4_irq_implement.h
#        ${v4_arm_core_path}/implements/v4_mem_implement.h
#        ${v4_arm_core_path}/implements/v4_multiply_implement.h
#        ${v4_arm_core_path}/implements/v4_psr_implement.h
#    )
#    set(v4_arm_core_src ${v4_arm_decoder_src} ${v4_arm_implement_src})

    set(header_core
        include/instruction_class.h
        include/framework/logger.h
        include/component/cpu/cpu_status.h
        include/component/component_class.h
        include/component/cpu/cpu_enum.h
        include/framework/gba_instance.h
        src/framework/gba_instance.cpp
        include/component/cpu/cpu.h
        include/component/memory/mmu_status.h
        include/component/memory/mmu.h
        include/component/io/io.h
        include/gba_bios.h
        include/utility/file_access.h
        include/component/memory/memory_region.h
        include/component/memory/mem_enum.h
        include/component/memory/general_memory.h
        include/component/memory/display_memory.h
        include/component/memory/gamepak_memory.h
        include/utility/bit_manipulate.h include/utility/gg_utility.h include/component/cpu/core/arm/decoder/multiply.h include/component/cpu/core/arm/decoder/memory_access.h
    )

    set(src_core)

    add_executable(ggAdv main.cpp ${header_core} ${v4_arm_core_src} ${src_core} include/component/memory/memory_exceptions.h include/component/io/io_enum.h include/component/memory/handler/bios_handler.h include/component/memory/handler/ewram_handler.h include/component/memory/handler/iwram_handler.h include/component/memory/handler/io_handler.h include/component/memory/handler/palette_handler.h include/component/memory/handler/mirror.h include/component/memory/handler/vram_handler.h include/component/memory/handler/oam_handler.h include/component/memory/handler/handler_table.h include/component/memory/handler/gamepak_handler.h include/component/memory/handler/sram_handler.h include/component/cartridge.h include/component/memory/eeprom.h)
    target_link_libraries(ggAdv /usr/local/lib/libfmt.a)
    target_include_directories(ggAdv PUBLIC
        include
        include/component
        include/component/cpu
        include/component/cpu/core
        include/component/cpu/core/arm
        include/component/cpu/core/arm/decoder
        include/component/cpu/core/arm/implements
        include/component/io
        include/component/memory
        include/framework
        include/utility
        spdlog/include
    )

project(arm_analyzer)
add_executable(arm_analyzer tool/arm_analyzer/main.cpp)
target_include_directories(arm_analyzer PUBLIC
        tool/arm_analyzer
        )

target_link_libraries(arm_analyzer /usr/local/lib/libfmt.a /usr/local/lib/libcapstone.so)

project(ggBenchmark)
add_executable(ggBenchmark ${header_core} ${header_arm_implement} ${src_core} ggBenchmark/main.cpp)
target_include_directories(ggBenchmark PUBLIC
        include
        include/component/
        include/component/cpu
        include/component/cpu/core
        include/component/cpu/core/arm
        include/component/cpu/core/arm/decoder
        include/component/cpu/core/arm/implements
        include/component/memory
        include/component/io
        include/framework
        include/instruction/arm
        include/component/cpu/core/arm/implements
        include/utility
    spdlog/include
        )
target_link_libraries(ggBenchmark /usr/local/lib/libfmt.a
        /usr/local/lib/libbenchmark.a
        /usr/local/lib/libbenchmark_main.a)

project(ggTest)

include_directories(./eggvance/eggvance/external/shell/include)
include_directories(./eggvance/eggvance/external/icon/eggvance/include)
include_directories(./eggvance/eggvance/src)

file(GLOB_RECURSE SOURCE_FILES
        ./eggvance/eggvance/src/*.h
        ./eggvance/eggvance/src/*.cpp
        )

add_executable(ggTest ${SOURCE_FILES} ${header_core} ${header_arm_implement} ${src_core} ggTest/gg_test.h ggTest/include/loop_tool.h ggTest/alu.cpp ggTest/multiply.cpp ggTest/mul_long.cpp ggTest/branch.cpp ggTest/swap.cpp ggTest/ldr.cpp ggTest/str.cpp ggTest/ldrh.cpp ggTest/strh.cpp ggTest/ldm.cpp ggTest/stm.cpp ggTest/interrupt_and_misc.cpp ggTest/unpredictable.cpp)

target_include_directories(ggTest PUBLIC
        include
        include/component/
        include/component/cpu
        include/component/cpu/core
        include/component/cpu/core/arm
        include/component/cpu/core/arm/decoder
        include/component/cpu/core/arm/implements
        include/component/memory
        include/component/io
        include/framework
        include/instruction/arm
        include/component/cpu/core/arm/implements
        include/utility
        ./eggvance/eggvance/src/
        ./eggvance/eggvance/external/shell/include/
        ggTest
        ggTest/include
    spdlog/include
        )

target_link_libraries(ggTest /usr/local/lib/libfmt.a
        /usr/local/lib/libgtest.a
        /usr/local/lib/libgtest_main.a
        /usr/local/lib/libkeystone.so
        /usr/local/lib/libcapstone.a
        SDL2
        stdc++fs
        )
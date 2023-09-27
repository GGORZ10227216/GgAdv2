cmake_minimum_required(VERSION 3.16)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKXX_FLAGS} -D_REENTRANT -I/usr/include/SDL2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -O3")

project(ggAdv)

add_subdirectory(libppu)

set(header_core
        include/instruction_class.h
        include/component/cpu/cpu_status.h
        include/component/component_class.h
        include/component/cpu/cpu_enum.h
        include/framework/gba_instance.h
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
#        include/component/sub_module/timer.h
#        include/component/sub_module/dma/dma_controller.h
#        include/component/sub_module/dma/dma.h
        )

set(src_core
        src/framework/gba_instance.cpp
#        src/component/sub_module/timers.cpp
        src/component/cpu/cpu.cpp
        src/component/memory/mmu.cpp
        src/component/memory/io_handler.cpp
#        src/component/sub_module/dma/dma.cpp
        )

# include/component/cpu/core/arm_encoder_v2.h include/component/cpu/core/thumb/decoder/type1.h
add_executable(ggAdv main.cpp ${header_core} ${src_core})
target_compile_definitions(ggAdv PUBLIC -DSPDLOG_SHARED_LIB -DSPDLOG_COMPILED_LIB -DSPDLOG_FMT_EXTERNAL)
target_link_libraries(ggAdv -lfmt -lspdlog -lcapstone -lkeystone -lgtest -lgtest_main libppu)

target_include_directories(ggAdv PUBLIC
        include
        include/component
        include/component/cpu
        include/component/cpu/core
        include/component/cpu/core/arm
        include/component/cpu/core/arm/decoder
        include/component/cpu/core/arm/implements
        include/component/cpu/core/thumb/implements
        include/component/io
        include/component/memory
        include/component/sub_module
        include/framework
        include/utility
        libppu/include
        )
cmake_minimum_required(VERSION 3.16)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKXX_FLAGS} -D_REENTRANT -I/usr/include/SDL2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -O3")

project(ggAdv)

add_subdirectory(libppu)

set(src_core
        src/framework/gba_instance.cpp
        src/framework/gg_texture.cpp
        src/framework/glad.c
        src/component/cpu/cpu.cpp
        src/component/memory/mmu.cpp
        src/component/sub_module/dma/transfer_channel.cpp
        src/component/sub_module/dma/controller.cpp
        src/component/sub_module/timer/timer.cpp
        src/component/sub_module/apu/apu.cpp
        src/component/sub_module/keypad/keypad.cpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_executable(ggAdv main.cpp ${src_core})
target_link_libraries(ggAdv fmt keystone libppu)
target_link_libraries(ggAdv ${CMAKE_CURRENT_SOURCE_DIR}/lib/libcapstone.a)
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
        include/component/memory/handler
        include/component/sub_module
        include/component/sub_module/apu
        include/framework
        include/utility
        libppu/include
        tool/capstone/include
        )
cmake_minimum_required(VERSION 3.15)
project(bscanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

find_package(PkgConfig REQUIRED)

set(TRITON_ROOT "" CACHE PATH "Path to Triton installation")
if(TRITON_ROOT)
    set(CMAKE_PREFIX_PATH ${TRITON_ROOT} ${CMAKE_PREFIX_PATH})
endif()

find_path(TRITON_INCLUDE_DIR
    NAMES triton/api.hpp
    PATHS
        ${TRITON_ROOT}/include
        /usr/include
        /usr/local/include
        /opt/triton/include
    DOC "Triton include directory"
)

find_library(TRITON_LIBRARY
    NAMES triton
    PATHS
        ${TRITON_ROOT}/lib
        /usr/lib
        /usr/local/lib
        /opt/triton/lib
    DOC "Triton library"
)

if(NOT TRITON_INCLUDE_DIR OR NOT TRITON_LIBRARY)
    message(FATAL_ERROR "Triton library not found. Please install Triton or set TRITON_ROOT")
endif()

include_directories(${TRITON_INCLUDE_DIR})

set(SOURCES
    src/main.cpp
    src/cli_parser.cpp
    src/binary_analyzer.cpp
    src/elf_format.cpp
    src/pe_format.cpp
    src/triton_engine.cpp
    src/io_tracker.cpp
)

add_executable(bscanner ${SOURCES})

target_link_libraries(bscanner ${TRITON_LIBRARY})

if(UNIX AND NOT APPLE)
    target_link_libraries(bscanner pthread dl)
endif()

if(WIN32)
    target_link_libraries(bscanner ws2_32)
endif()

install(TARGETS bscanner
    RUNTIME DESTINATION bin
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        target_compile_options(bscanner PRIVATE /W4)
    else()
        target_compile_options(bscanner PRIVATE -Wall -Wextra -g)
    endif()
endif()

set_target_properties(bscanner PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)
cmake_minimum_required(VERSION 3.16)
project(cvrptw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS ON)
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
endif()

file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ROOT)
message(STATUS "Got root of repository: ${ROOT}")

file(GLOB_RECURSE COMMON CONFIGURE_DEPENDS "${ROOT}/src/common/*.cpp")

add_executable(reader "${ROOT}/src/reader.cpp" "${COMMON}")
target_include_directories(
    reader PRIVATE
    "${ROOT}/include"
)
target_precompile_headers(reader PRIVATE "${ROOT}/include/pch.hpp")

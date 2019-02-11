cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall -U__STRICT_ANSI__ -std=c++17")

project(net LANGUAGES CXX)

configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download" )
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download" )

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_subdirectory("${CMAKE_BINARY_DIR}/googletest-src"
                 "${CMAKE_BINARY_DIR}/googletest-build")

find_package(Boost COMPONENTS program_options REQUIRED)
include_directories(.)

add_library(net net.cpp)

add_executable(requester requester.cpp)
target_link_libraries(requester net Boost::program_options)
add_executable(sender sender.cpp)
target_link_libraries(sender net Boost::program_options)
add_executable(emulator emulator.cpp)
target_link_libraries(emulator net Boost::program_options)
add_executable(router router.cpp)
target_link_libraries(router net Boost::program_options)

add_executable(test_net test_net.cpp)
target_link_libraries(test_net net gtest_main)

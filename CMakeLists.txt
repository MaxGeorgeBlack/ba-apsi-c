cmake_minimum_required(VERSION 3.18)
project(ba_apsi_c_bench VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BA_SANITIZE "Address and undefined behavior sanitizers" OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_path(PBC_INCLUDE_DIR pbc/pbc.h REQUIRED)
find_library(PBC_LIBRARY pbc REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)

add_compile_options(-Wall -Wextra -Wshadow -Wformat=2)
if(BA_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(baapsi STATIC src/util.c src/ec.c src/dlp.c src/dlp_prepared.c src/protocol.c)
target_include_directories(baapsi PUBLIC include ${PBC_INCLUDE_DIR})
target_link_libraries(baapsi PUBLIC ${PBC_LIBRARY} ${GMP_LIBRARY} OpenSSL::Crypto)

add_executable(ba_bench src/bench.c)
target_link_libraries(ba_bench PRIVATE baapsi)

add_executable(ba_tests tests/test.c)
target_link_libraries(ba_tests PRIVATE baapsi)
target_compile_definitions(ba_bench PRIVATE BA_DEFAULT_PARAMS="${CMAKE_CURRENT_SOURCE_DIR}/params/type-a-160-512.param")
enable_testing()
add_test(NAME correctness COMMAND ba_tests ${CMAKE_CURRENT_SOURCE_DIR}/params/type-a-160-512.param)
set_tests_properties(correctness PROPERTIES TIMEOUT 180)
add_executable(ba_prepared_tests tests/test_dlp_prepared.c)
target_link_libraries(ba_prepared_tests PRIVATE baapsi)
add_test(NAME prepared_recovery_correctness COMMAND ba_prepared_tests ${CMAKE_CURRENT_SOURCE_DIR}/params/type-a-160-512.param)
set_tests_properties(prepared_recovery_correctness PROPERTIES TIMEOUT 180)

add_executable(ba_dlp_bench src/dlp_bench.c)
target_link_libraries(ba_dlp_bench PRIVATE baapsi)

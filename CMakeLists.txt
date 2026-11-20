cmake_minimum_required(VERSION 3.28)
project(BlindVault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(P2P_BUILD_TESTS "Build the unit tests" ON)
option(P2P_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer (GCC/Clang only)" OFF)
option(P2P_BUILD_GUI "Build the Qt6 desktop application" OFF)

if (WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00) # Windows 10/11
endif()

# Sanitizers add checks that turn memory errors into loud crashes
if(P2P_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "P2P_SANITIZE needs GCC or Clang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Find core backend dependencies
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

# ---------------- Core Static Library ----------------
add_library(blindvault_core STATIC
        src/security/identity.cpp
        src/security/trust_store.cpp
        src/security/tls_trust.cpp
        src/transport/client_node.cpp
        src/transport/server_session.cpp
        src/transport/server_node.cpp
        src/transport/control/control_client.cpp
        src/vault/at_rest_crypto.cpp
        src/vault/kms_provider.cpp
        src/vault/tokenizer.cpp
        src/vault/vault_index.cpp
        src/vault/s3_shard_backend.cpp
        src/vault/vault_gateway.cpp
)
target_include_directories(blindvault_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/vault
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/client
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/control
        ${CMAKE_CURRENT_SOURCE_DIR}/include/security
)
target_compile_options(blindvault_core PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
)
target_link_libraries(blindvault_core PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        ${CMAKE_DL_LIBS}
)

# ---------------- CLI Application ----------------
add_executable(BlindVault
        src/main.cpp
        include/vault/cli_benchmark.hpp
        include/transport/client/p2p_node.hpp
        include/security/cli_identity.hpp
        gui/log_redirect.hpp
)
target_compile_options(BlindVault PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
)
target_link_libraries(BlindVault PRIVATE blindvault_core)

# ---------------- Qt 6 GUI Application ----------------
if(P2P_BUILD_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)

    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

    add_executable(BlindVault_GUI
            gui/main_gui.cpp
            gui/main_window.hpp
            gui/main_window.cpp
            gui/network_bridge.hpp
            gui/network_bridge.cpp
            gui/log_redirect.hpp
    )
    target_include_directories(BlindVault_GUI PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/gui
    )
    target_compile_options(BlindVault_GUI PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/W4>
            $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
    )
    target_link_libraries(BlindVault_GUI PRIVATE
            blindvault_core
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
    )
endif()

# ---------------- Fuzzing (Clang only) ----------------
option(P2P_BUILD_FUZZERS "Build the libFuzzer fuzz targets (Clang only)" OFF)
if(P2P_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "P2P_BUILD_FUZZERS needs Clang (it uses libFuzzer)")
    endif()
    add_executable(fuzz_validation fuzz/fuzz_validation.cpp)
    target_compile_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -O1 -g)
    target_link_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_validation PRIVATE blindvault_core)
endif()

# ---------------- Unit tests ----------------
if(P2P_BUILD_TESTS)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(unit_tests
            tests/test_protocol.cpp
            tests/test_validation.cpp
            tests/test_disk_budget.cpp
            tests/test_trust_store.cpp
            tests/test_identity.cpp
            tests/test_tls_trust.cpp
            tests/test_hashing.cpp
            tests/test_e2e_trust.cpp
            tests/test_vault_core.cpp
    )
    target_compile_options(unit_tests PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/W4>
            $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
    )
    target_link_libraries(unit_tests PRIVATE blindvault_core GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(unit_tests)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME end_to_end
                COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_test.sh $<TARGET_FILE:BlindVault>)
    endif()
endif()

# ---------------- Microbenchmarks (Google Benchmark) ----------------
option(P2P_BUILD_BENCHMARKS "Build Google Benchmark suite for CI tracking" OFF)
if(P2P_BUILD_BENCHMARKS)
    include(FetchContent)
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(googlebenchmark
            URL https://github.com/google/benchmark/archive/refs/tags/v1.9.2.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googlebenchmark)

    add_executable(bench_vault benchmarks/bench_vault.cpp)
    target_compile_options(bench_vault PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/W4>
            $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
    )
    target_link_libraries(bench_vault PRIVATE blindvault_core benchmark::benchmark_main)
endif()

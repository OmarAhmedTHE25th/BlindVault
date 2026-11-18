cmake_minimum_required(VERSION 3.28)
project(P2P_Secure_File_Sharing)

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

# ---------------- CLI Application ----------------
add_executable(P2P_Secure_File_Sharing
        src/main.cpp
        include/transport/common/protocol.hpp
        include/security/validation.hpp
        include/security/disk_budget.hpp
        include/security/trust_store.hpp
        include/security/identity.hpp
        include/security/cli_identity.hpp
        include/security/tls_trust.hpp
        include/transport/common/file_streaming.hpp
        include/transport/client/client_node.hpp
        include/transport/server/server_session.hpp
        include/transport/server/server_node.hpp
        include/transport/client/p2p_node.hpp
        gui/log_redirect.hpp
        include/transport/common/events.hpp
        include/vault/at_rest_crypto.hpp
        include/vault/tokenizer.hpp
        include/vault/vault_index.hpp
        include/vault/vault_gateway.hpp
)
target_include_directories(P2P_Secure_File_Sharing PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/vault
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/client
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include/security
)
target_link_libraries(P2P_Secure_File_Sharing PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
)

# ---------------- Qt 6 GUI Application ----------------
if(P2P_BUILD_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)

    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

    add_executable(P2P_Secure_File_Sharing_GUI
            gui/main_gui.cpp
            gui/main_window.hpp
            gui/main_window.cpp
            gui/network_bridge.hpp
            gui/network_bridge.cpp
            include/transport/common/protocol.hpp
            include/security/validation.hpp
            include/security/disk_budget.hpp
            include/security/trust_store.hpp
            include/security/identity.hpp
            include/security/cli_identity.hpp
            include/security/tls_trust.hpp
            include/transport/common/file_streaming.hpp
            include/transport/client/client_node.hpp
            include/transport/server/server_session.hpp
            include/transport/server/server_node.hpp
            gui/network_bridge.hpp
            gui/main_window.cpp
            gui/main_window.hpp
            gui/main_gui.cpp
            gui/main_gui.cpp
            gui/network_bridge.cpp
            gui/log_redirect.hpp
            include/transport/common/events.hpp
            include/vault/at_rest_crypto.hpp
            include/vault/tokenizer.hpp
            include/vault/vault_index.hpp
            include/vault/vault_gateway.hpp
    )

    target_include_directories(P2P_Secure_File_Sharing_GUI PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/include/vault
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/client
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/common
            ${CMAKE_CURRENT_SOURCE_DIR}/include/security
            ${CMAKE_CURRENT_SOURCE_DIR}/gui
    )

    target_link_libraries(P2P_Secure_File_Sharing_GUI PRIVATE
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            OpenSSL::SSL
            OpenSSL::Crypto
            Boost::system
    )
endif()

# ---------------- Fuzzing (Clang only) ----------------
option(P2P_BUILD_FUZZERS "Build the libFuzzer fuzz targets (Clang only)" OFF)
if(P2P_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "P2P_BUILD_FUZZERS needs Clang (it uses libFuzzer)")
    endif()
    add_executable(fuzz_validation fuzz/fuzz_validation.cpp)
    target_include_directories(fuzz_validation PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/common
            ${CMAKE_CURRENT_SOURCE_DIR}/include/security)
    target_compile_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -O1 -g)
    target_link_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_validation PRIVATE Boost::system)
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
            include/vault/at_rest_crypto.hpp
            include/vault/tokenizer.hpp
            include/vault/vault_index.hpp
            include/vault/vault_gateway.hpp
            tests/test_vault_core.cpp
    )
    target_include_directories(unit_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/include/vault
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/client
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include/transport/common
            ${CMAKE_CURRENT_SOURCE_DIR}/include/security)
    target_link_libraries(unit_tests PRIVATE GTest::gtest_main OpenSSL::Crypto OpenSSL::SSL Boost::system)

    include(GoogleTest)
    gtest_discover_tests(unit_tests)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME end_to_end
                COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_test.sh $<TARGET_FILE:P2P_Secure_File_Sharing>)
    endif()
endif()
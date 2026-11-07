cmake_minimum_required(VERSION 3.22)

project(miniips VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "miniips targets Linux. Use Ubuntu 24.04 LTS or compatible Linux.")
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
    message(FATAL_ERROR "miniips requires a GCC or Clang C++20 toolchain.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(MINIIPS_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(MINIIPS_ENABLE_CLANG_TIDY "Run clang-tidy when compiling project sources" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)

if(MINIIPS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(MINIIPS_ENABLE_CLANG_TIDY)
    find_program(MINIIPS_CLANG_TIDY NAMES clang-tidy-18 clang-tidy REQUIRED)
    set(CMAKE_CXX_CLANG_TIDY "${MINIIPS_CLANG_TIDY};--warnings-as-errors=*")
endif()

# System packages only: configuration never downloads third-party source code.
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap>=1.5.1)
pkg_check_modules(NFQUEUE REQUIRED IMPORTED_TARGET libnetfilter_queue)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

add_library(miniips_packet STATIC src/packet_parser.cpp src/pcap_source.cpp)
target_include_directories(miniips_packet PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(miniips_packet PRIVATE PkgConfig::PCAP)

add_library(miniips_flow STATIC src/flow_table.cpp)
target_include_directories(miniips_flow PUBLIC "${PROJECT_SOURCE_DIR}/include")

add_library(miniips_reassembly STATIC src/tcp_reassembler.cpp)
target_link_libraries(miniips_reassembly PUBLIC miniips_flow)

add_library(miniips_cli STATIC src/cli.cpp)

add_library(miniips_rules STATIC src/rule_loader.cpp src/rule_engine.cpp)
target_link_libraries(miniips_rules PUBLIC miniips_reassembly nlohmann_json::nlohmann_json)
target_link_libraries(miniips_cli PRIVATE miniips_packet miniips_flow miniips_reassembly miniips_rules)
target_include_directories(miniips_cli PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(miniips_cli PRIVATE MINIIPS_VERSION="${PROJECT_VERSION}")

add_executable(miniips src/main.cpp)
target_link_libraries(miniips PRIVATE
    miniips_cli
    PkgConfig::PCAP
    PkgConfig::NFQUEUE
    nlohmann_json::nlohmann_json
    spdlog::spdlog
)

include(CTest)
if(BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)
    add_subdirectory(tests)
endif()

find_program(MINIIPS_CLANG_FORMAT NAMES clang-format-18 clang-format)
if(MINIIPS_CLANG_FORMAT)
    add_custom_target(format-check
        COMMAND "${MINIIPS_CLANG_FORMAT}" --dry-run --Werror
            include/miniips/cli.hpp include/miniips/packet.hpp
            include/miniips/packet_parser.hpp include/miniips/capture_source.hpp
            include/miniips/flow.hpp include/miniips/flow_table.hpp
            src/flow_table.cpp tests/test_flow_table.cpp
            include/miniips/tcp_reassembler.hpp src/tcp_reassembler.cpp
            tests/test_tcp_reassembler.cpp tests/test_reassembly_lifecycle.cpp
            tests/test_cli_reassembly.cpp tests/fixtures/reassembly_fixtures.hpp
            include/miniips/rule.hpp include/miniips/rule_loader.hpp src/rule_loader.cpp
            tests/test_rule_loader.cpp
            include/miniips/detection_decision.hpp include/miniips/rule_engine.hpp
            src/rule_engine.cpp tests/test_rule_engine.cpp tests/test_reassembly_ranges.cpp
            tests/fixtures/rule_fixtures.hpp
            tests/test_cli_rules.cpp
            tests/test_cli_flow.cpp tests/fixtures/flow_fixtures.hpp
            src/cli.cpp src/main.cpp src/packet_parser.cpp src/pcap_source.cpp
            tests/test_cli.cpp tests/test_packet_parser.cpp tests/test_pcap_source.cpp
            tests/test_cli_pcap.cpp tests/fixture_writer.cpp
            tests/pcap_fixture.hpp tests/fixtures/packet_fixtures.hpp
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        COMMENT "Checking C++ formatting"
        VERBATIM
    )
else()
    message(STATUS "clang-format not found; install it to enable the format-check target.")
endif()

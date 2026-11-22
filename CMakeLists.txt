cmake_minimum_required(VERSION 3.20...4.4)
project(CycloneDX_DSL VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SBOM_DSL_BUILD_TESTS "Build the doctest unit test suite" ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

# Dependencies via FetchContent
include(FetchContent)

# nlohmann/json: the official release tarball (~110 KB) is much faster to fetch
# than a full clone of the repository.
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
)
FetchContent_MakeAvailable(nlohmann_json)

# Core Library Sources
set(CORE_SOURCES
    src/common/diagnostic.cpp
    src/lexer/lexer.cpp
    src/lexer/token.cpp
    src/ast/ast_printer.cpp
    src/parser/parser.cpp
    src/semantic/schema_catalog.cpp
    src/semantic/type_checker.cpp
    src/ir/ir_printer.cpp
    src/ir/ir_optimizer.cpp
    src/lowering/query_lowerer.cpp
    src/backend/native_engine.cpp
    src/backend/sbom_utility_codegen.cpp
    src/backend/result_formatter.cpp
    src/cli/cli_options.cpp
)

add_library(sbom_dsl_lib STATIC ${CORE_SOURCES})
target_include_directories(sbom_dsl_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(sbom_dsl_lib PUBLIC nlohmann_json::nlohmann_json)

# CLI Main Executable
add_executable(sbom-dsl src/main.cpp)
target_link_libraries(sbom-dsl PRIVATE sbom_dsl_lib)

install(TARGETS sbom-dsl RUNTIME DESTINATION bin)

# Testing
if(SBOM_DSL_BUILD_TESTS)
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.5.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(doctest)

    enable_testing()

    foreach(test_name IN ITEMS test_lexer test_parser test_semantic test_lowering test_backend test_e2e)
        add_executable(${test_name} tests/${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE sbom_dsl_lib doctest::doctest)
        target_compile_definitions(${test_name} PRIVATE
            TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()

    # test_e2e invokes the CLI binary, so it must be built first.
    add_dependencies(test_e2e sbom-dsl)
endif()

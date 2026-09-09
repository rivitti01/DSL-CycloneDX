cmake_minimum_required(VERSION 3.20)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version" FORCE)
project(CycloneDX_DSL VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

# Dependencies via FetchContent
include(FetchContent)

# nlohmann/json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# doctest for unit testing
FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11
)
FetchContent_MakeAvailable(doctest)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

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

# Testing
enable_testing()
add_compile_definitions(TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

add_executable(test_lexer tests/test_lexer.cpp)
target_link_libraries(test_lexer PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_lexer COMMAND test_lexer)

add_executable(test_parser tests/test_parser.cpp)
target_link_libraries(test_parser PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_parser COMMAND test_parser)

add_executable(test_semantic tests/test_semantic.cpp)
target_link_libraries(test_semantic PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_semantic COMMAND test_semantic)

add_executable(test_lowering tests/test_lowering.cpp)
target_link_libraries(test_lowering PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_lowering COMMAND test_lowering)

add_executable(test_backend tests/test_backend.cpp)
target_link_libraries(test_backend PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_backend COMMAND test_backend)

add_executable(test_e2e tests/test_e2e.cpp)
target_link_libraries(test_e2e PRIVATE sbom_dsl_lib doctest::doctest)
add_test(NAME test_e2e COMMAND test_e2e)

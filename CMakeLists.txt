cmake_minimum_required(VERSION 3.16)
project(ghostline_gate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GHOSTLINE_BUILD_QT "Build the embedded Qt operator shell" ON)

add_library(ghostline_core
    src/audit.cpp
    src/builtin_plugins.cpp
    src/operator_state.cpp
    src/pid_search.cpp
    src/plugin_registry.cpp
    src/transport_core.cpp
)

target_include_directories(ghostline_core PUBLIC include)
target_compile_options(ghostline_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(ghostline_cli src/main.cpp)
target_link_libraries(ghostline_cli PRIVATE ghostline_core)

enable_testing()
add_executable(ghostline_tests tests/ghostline_tests.cpp)
target_link_libraries(ghostline_tests PRIVATE ghostline_core)
add_test(NAME ghostline_tests COMMAND ghostline_tests)
add_test(NAME ghostline_rules_loader COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/test_rules_loader.py)

if(GHOSTLINE_BUILD_QT)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    if(Qt6_FOUND)
        qt_standard_project_setup()
        add_executable(ghostline_qt src/qt_operator_main.cpp)
        target_link_libraries(ghostline_qt PRIVATE Qt6::Widgets ghostline_core)
    else()
        message(WARNING "Qt6 Widgets not found; ghostline_qt target will not be built.")
    endif()
endif()

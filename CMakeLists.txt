cmake_minimum_required(VERSION 3.12)
project(IdentityLeakAnalyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Configure C++ standard limits
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Register project headers search path
include_directories(include)

# Configure strict compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Define modular static library
add_library(analyzer_core STATIC
    src/profile_parser.cpp
    src/threat_feed.cpp
    src/analyzer_engine.cpp
)

# Define command-line application target
add_executable(identity_leak_analyzer
    src/main.cpp
)

# Setup library linking dependencies
find_package(Threads REQUIRED)
target_link_libraries(analyzer_core PUBLIC Threads::Threads)
target_link_libraries(identity_leak_analyzer PRIVATE analyzer_core)

# Define unit tests target
add_executable(leak_analyzer_tests
    tests/test_suite.cpp
)
target_link_libraries(leak_analyzer_tests PRIVATE analyzer_core)

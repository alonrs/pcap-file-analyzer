cmake_minimum_required(VERSION 3.0)

project(PcapAnalyzer LANGUAGES CXX)

# Set custom debug and release flags
set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} \
    -O0 -march=native -Wall")
set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} \
    -O2 -march=native -Wall -DNDEBUG -flto")

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Find the pkg-config tool
find_package(PkgConfig REQUIRED)

# Use pkg-config to find the pcap library
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(tool-pcap-analyzer.exe
               src/arguments.cpp
               src/tool-pcap-analyzer.cpp
               src/log.cpp)
target_include_directories(tool-pcap-analyzer.exe
                           PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(tool-pcap-analyzer.exe ${PCAP_LIBRARIES})
set_target_properties(tool-pcap-analyzer.exe
                      PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                      "${CMAKE_BINARY_DIR}")

add_executable(tool-locality-stats.exe
               src/arguments.cpp
               src/tool-locality-stats.cpp
               src/log.cpp)
target_include_directories(tool-locality-stats.exe
                           PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(tool-locality-stats.exe ${PCAP_LIBRARIES})
set_target_properties(tool-locality-stats.exe
                      PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                      "${CMAKE_BINARY_DIR}")

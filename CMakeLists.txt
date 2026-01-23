cmake_minimum_required(VERSION 3.16)
project(http_a
  VERSION 1.0.0
  DESCRIPTION "Async HTTP/1.1 & HTTP/2 server library built on h2o"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(HTTP_A_BUILD_EXAMPLES "Build example applications" ON)
option(HTTP_A_BUILD_TESTS "Build test applications" ON)

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------

# nlohmann/json - fetched from GitHub
include(FetchContent)
FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(json)

# h2o - expect pre-installed static library
# User must set H2O_ROOT or have h2o installed in standard paths
find_path(H2O_INCLUDE_DIR
  NAMES h2o.h
  PATHS
    ${H2O_ROOT}/include
    /usr/local/include
    /usr/include
  DOC "h2o include directory"
)

find_library(H2O_LIBRARY
  NAMES h2o libh2o.a
  PATHS
    ${H2O_ROOT}/lib
    ${H2O_ROOT}
    /usr/local/lib
    /usr/lib
  DOC "h2o static library"
)

if(NOT H2O_INCLUDE_DIR OR NOT H2O_LIBRARY)
  message(FATAL_ERROR
    "h2o library not found.\n"
    "Please set H2O_ROOT to the h2o installation directory, or ensure h2o is installed.\n"
    "  cmake -DH2O_ROOT=/path/to/h2o ..\n"
    "See: https://github.com/h2o/h2o"
  )
endif()

message(STATUS "Found h2o: ${H2O_LIBRARY}")
message(STATUS "h2o include: ${H2O_INCLUDE_DIR}")

# OpenSSL
find_package(OpenSSL REQUIRED)

# libuv
find_path(UV_INCLUDE_DIR
  NAMES uv.h
  PATHS /usr/local/include /usr/include
)
find_library(UV_LIBRARY
  NAMES uv libuv
  PATHS /usr/local/lib /usr/lib
)
if(NOT UV_INCLUDE_DIR OR NOT UV_LIBRARY)
  message(FATAL_ERROR "libuv not found. Please install libuv.")
endif()

# zlib
find_package(ZLIB REQUIRED)

# brotli
find_path(BROTLI_INCLUDE_DIR
  NAMES brotli/decode.h
  PATHS /usr/local/include /usr/include
)
find_library(BROTLI_DEC_LIBRARY
  NAMES brotlidec
  PATHS /usr/local/lib /usr/lib
)
find_library(BROTLI_ENC_LIBRARY
  NAMES brotlienc
  PATHS /usr/local/lib /usr/lib
)
find_library(BROTLI_COMMON_LIBRARY
  NAMES brotlicommon
  PATHS /usr/local/lib /usr/lib
)
if(NOT BROTLI_INCLUDE_DIR OR NOT BROTLI_DEC_LIBRARY)
  message(FATAL_ERROR "Brotli not found. Please install libbrotli.")
endif()

# pthread
find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# http_a library (header-only interface)
# -----------------------------------------------------------------------------

add_library(http_a INTERFACE)
add_library(http_a::http_a ALIAS http_a)

target_include_directories(http_a INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/http_a>
  ${H2O_INCLUDE_DIR}
  ${UV_INCLUDE_DIR}
  ${BROTLI_INCLUDE_DIR}
)

# For build: link directly to fetched nlohmann_json
# For install: the config file will find_package(nlohmann_json)
target_link_libraries(http_a INTERFACE
  $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
  ${H2O_LIBRARY}
  OpenSSL::SSL
  OpenSSL::Crypto
  ${UV_LIBRARY}
  ZLIB::ZLIB
  ${BROTLI_DEC_LIBRARY}
  ${BROTLI_ENC_LIBRARY}
  ${BROTLI_COMMON_LIBRARY}
  Threads::Threads
)

target_compile_features(http_a INTERFACE cxx_std_20)

# -----------------------------------------------------------------------------
# Examples
# -----------------------------------------------------------------------------

if(HTTP_A_BUILD_EXAMPLES)
  add_executable(hello_world examples/hello_world.cc)
  target_link_libraries(hello_world PRIVATE http_a)

  add_executable(file_serve examples/file_serve.cc)
  target_link_libraries(file_serve PRIVATE http_a)

  add_executable(rest_api examples/rest_api.cc)
  target_link_libraries(rest_api PRIVATE http_a)
endif()

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

if(HTTP_A_BUILD_TESTS)
  add_executable(test_0_sync_complex tests/test_0_sync_complex.cc)
  target_link_libraries(test_0_sync_complex PRIVATE http_a)

  add_executable(test_1_async_interactive tests/test_1_async_interactive.cc)
  target_link_libraries(test_1_async_interactive PRIVATE http_a)

  add_executable(test_2_async_file tests/test_2_async_file.cc)
  target_link_libraries(test_2_async_file PRIVATE http_a)

  add_executable(test_3_async_exec tests/test_3_async_exec.cc)
  target_link_libraries(test_3_async_exec PRIVATE http_a)

  add_executable(test_4_async_handler tests/test_4_async_handler.cc)
  target_link_libraries(test_4_async_handler PRIVATE http_a)
endif()

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS http_a
  EXPORT http_a-targets
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/http_a
  FILES_MATCHING PATTERN "*.hh"
)

install(EXPORT http_a-targets
  FILE http_a-targets.cmake
  NAMESPACE http_a::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/http_a
)

# Config file for find_package
include(CMakePackageConfigHelpers)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/http_a-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/http_a-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/http_a
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/http_a-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/http_a-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/http_a-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/http_a
)


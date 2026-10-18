cmake_minimum_required(VERSION 3.20)
# Única fuente de la versión: título, barra de estado y Propiedades del .exe.
project(NetAnalyzer VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # compile_commands.json para clangd / clang-tidy
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()
# Runtime estático en MSVC: el .exe funciona sin instalar Visual C++ Redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(NETANALYZER_TESTS "Compilar los tests" ON)
option(NETANALYZER_WARNINGS_AS_ERRORS "Tratar los avisos del compilador como errores" OFF)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(CompilerWarnings)
include(Dependencies)

add_subdirectory(src)

if(NETANALYZER_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

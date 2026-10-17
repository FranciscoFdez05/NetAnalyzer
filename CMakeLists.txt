cmake_minimum_required(VERSION 3.20)
# Única fuente de la versión: título, barra de estado y Propiedades del .exe.
project(NetAnalyzer VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()
# Runtime estático en MSVC: el .exe funciona sin instalar Visual C++ Redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- dependencias (se descargan solas la primera vez, versión y hash fijos)
include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)  # fecha de extracción = ahora (evita recompilaciones raras)
endif()
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(glfw
  URL https://github.com/glfw/glfw/archive/refs/tags/3.4.tar.gz
  URL_HASH SHA256=c038d34200234d071fae9345bc455e4a8f2f544ab60150765d7704e08f3dac01)
FetchContent_Declare(imgui
  URL https://github.com/ocornut/imgui/archive/refs/tags/v1.90.9.tar.gz
  URL_HASH SHA256=04943919721e874ac75a2f45e6eb6c0224395034667bf508923388afda5a50bf)
FetchContent_Declare(implot
  URL https://github.com/epezent/implot/archive/refs/tags/v0.16.tar.gz
  URL_HASH SHA256=961df327d8a756304d1b0a67316eebdb1111d13d559f0d3415114ec0eb30abd1)
FetchContent_MakeAvailable(glfw imgui implot)

# nlohmann/json (un único header) para leer las respuestas de VirusTotal.
set(JSON_HPP ${CMAKE_BINARY_DIR}/_deps/nlohmann/include/nlohmann/json.hpp)
if(NOT EXISTS ${JSON_HPP})
  file(DOWNLOAD https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp ${JSON_HPP}
       EXPECTED_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6)
endif()

find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)

add_library(imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
  ${implot_SOURCE_DIR}/implot.cpp
  ${implot_SOURCE_DIR}/implot_items.cpp)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${implot_SOURCE_DIR})
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

# ---- núcleo (todo menos la interfaz): lo usan la aplicación y los tests
set(CORE_SOURCES tracker.cpp resolver.cpp collector.cpp common.cpp virustotal.cpp http.cpp sha256.cpp
                 reputation.cpp)
if(WIN32)
  list(APPEND CORE_SOURCES collector_win.cpp)
elseif(APPLE)
  list(APPEND CORE_SOURCES collector_macos.cpp)
else()
  list(APPEND CORE_SOURCES collector_linux.cpp)
endif()

add_library(netanalyzer_core STATIC ${CORE_SOURCES})
target_include_directories(netanalyzer_core PUBLIC ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}/_deps/nlohmann/include)
target_compile_definitions(netanalyzer_core PUBLIC NETANALYZER_VERSION="${PROJECT_VERSION}")
target_link_libraries(netanalyzer_core PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(netanalyzer_core PUBLIC iphlpapi ws2_32 dnsapi shell32 winhttp bcrypt)
  target_compile_definitions(netanalyzer_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00
                                                     _CRT_SECURE_NO_WARNINGS)
else()
  find_package(CURL REQUIRED)  # HTTPS para VirusTotal y listas (Linux: libcurl4-openssl-dev / libcurl-devel)
  target_link_libraries(netanalyzer_core PUBLIC CURL::libcurl resolv)  # resolv: consultas DNS TXT (Team Cymru)
endif()

# ---- aplicación
set(APP_SOURCES main.cpp app.cpp)
if(WIN32)
  configure_file(netanalyzer.rc.in ${CMAKE_BINARY_DIR}/netanalyzer.rc @ONLY)
  list(APPEND APP_SOURCES ${CMAKE_BINARY_DIR}/netanalyzer.rc)
endif()
add_executable(NetAnalyzer WIN32 ${APP_SOURCES})
target_link_libraries(NetAnalyzer PRIVATE netanalyzer_core imgui)

# ---- tests:  ctest --test-dir build -C Release --output-on-failure
option(NETANALYZER_TESTS "Compilar los tests" ON)
if(NETANALYZER_TESTS)
  enable_testing()
  add_executable(netanalyzer_tests tests.cpp)
  target_link_libraries(netanalyzer_tests PRIVATE netanalyzer_core)
  add_test(NAME netanalyzer_tests COMMAND netanalyzer_tests)
endif()

foreach(t netanalyzer_core NetAnalyzer netanalyzer_tests)
  if(NOT TARGET ${t})
    continue()
  endif()
  if(MSVC)
    target_compile_options(${t} PRIVATE /utf-8 /W4)
  else()
    target_compile_options(${t} PRIVATE -Wall -Wextra)
  endif()
endforeach()
if(MSVC)
  target_compile_options(imgui PRIVATE /utf-8)
  target_link_options(NetAnalyzer PRIVATE /ENTRY:mainCRTStartup)  # main() sin consola
endif()

# El ejecutable final queda en la carpeta raíz del proyecto.
set_target_properties(NetAnalyzer PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_SOURCE_DIR})

# Dependencias externas: se descargan solas la primera vez, con versión y hash fijos.
#   glfw   -> ventana y entrada
#   imgui  -> interfaz (incluye ImPlot, se compila como una sola biblioteca estática)
#   nlohmann_json -> leer las respuestas de VirusTotal (un único header)
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

find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)

# ---- imgui + backends + implot
add_library(imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
  ${implot_SOURCE_DIR}/implot.cpp
  ${implot_SOURCE_DIR}/implot_items.cpp)
# SYSTEM: los avisos de código de terceros no se mezclan con los nuestros.
target_include_directories(imgui SYSTEM PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${implot_SOURCE_DIR})
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)
if(MSVC)
  target_compile_options(imgui PRIVATE /utf-8)
endif()

# ---- nlohmann/json
set(NLOHMANN_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/nlohmann/include)
set(JSON_HPP ${NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp)
if(NOT EXISTS ${JSON_HPP})
  file(DOWNLOAD https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp ${JSON_HPP}
       EXPECTED_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6)
endif()
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json SYSTEM INTERFACE ${NLOHMANN_INCLUDE_DIR})

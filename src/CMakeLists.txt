# ---- núcleo (todo menos la interfaz): lo usan la aplicación y los tests
add_library(netanalyzer_core STATIC
  core/collector.cpp
  core/common.cpp
  core/http.cpp
  core/reputation.cpp
  core/resolver.cpp
  core/sha256.cpp
  core/tracker.cpp
  core/virustotal.cpp)

# Recolector de sockets específico de cada SO.
if(WIN32)
  target_sources(netanalyzer_core PRIVATE platform/collector_win.cpp)
elseif(APPLE)
  target_sources(netanalyzer_core PRIVATE platform/collector_macos.cpp)
else()
  target_sources(netanalyzer_core PRIVATE platform/collector_linux.cpp)
endif()

# Los includes se escriben relativos a src/: #include "core/common.h"
target_include_directories(netanalyzer_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(netanalyzer_core PUBLIC NETANALYZER_VERSION="${PROJECT_VERSION}")
target_link_libraries(netanalyzer_core PUBLIC Threads::Threads PRIVATE nlohmann_json)
if(WIN32)
  target_link_libraries(netanalyzer_core PUBLIC iphlpapi ws2_32 dnsapi shell32 winhttp bcrypt)
  target_compile_definitions(netanalyzer_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00
                                                     _CRT_SECURE_NO_WARNINGS)
else()
  find_package(CURL REQUIRED)  # HTTPS para VirusTotal y listas (Linux: libcurl4-openssl-dev / libcurl-devel)
  target_link_libraries(netanalyzer_core PUBLIC CURL::libcurl resolv)  # resolv: consultas DNS TXT (Team Cymru)
endif()
netanalyzer_set_warnings(netanalyzer_core)

# ---- aplicación
add_executable(NetAnalyzer WIN32 app/main.cpp app/app.cpp)
if(WIN32)
  configure_file(${PROJECT_SOURCE_DIR}/resources/netanalyzer.rc.in ${CMAKE_CURRENT_BINARY_DIR}/netanalyzer.rc @ONLY)
  target_sources(NetAnalyzer PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/netanalyzer.rc)
endif()
target_link_libraries(NetAnalyzer PRIVATE netanalyzer_core imgui)
netanalyzer_set_warnings(NetAnalyzer)
if(MSVC)
  target_link_options(NetAnalyzer PRIVATE /ENTRY:mainCRTStartup)  # main() sin consola
endif()

# El ejecutable final queda en la carpeta raíz del proyecto.
set_target_properties(NetAnalyzer PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${PROJECT_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${PROJECT_SOURCE_DIR}
  RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${PROJECT_SOURCE_DIR})

#!/bin/sh
# Compila build/Release/NetAnalyzer en Linux o macOS. Requiere CMake y un compilador C++17.
set -e
cd "$(dirname "$0")"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
echo
echo "Listo: $(pwd)/build/Release/NetAnalyzer"

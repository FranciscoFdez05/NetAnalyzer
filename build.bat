@echo off
rem Compila NetAnalyzer.exe en build\Release. Requiere CMake y Visual Studio (C++).
cmake -S . -B build -A x64 || exit /b 1
cmake --build build --config Release --parallel || exit /b 1
echo.
echo Listo: %~dp0build\Release\NetAnalyzer.exe

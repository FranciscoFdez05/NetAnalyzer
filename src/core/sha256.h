// SHA-256 de archivos: BCrypt en Windows, implementación portable (FIPS 180-4) en el resto.
#pragma once

#include <string>

// Hash en hexadecimal (minúsculas) del archivo; "" si no se puede leer.
std::string sha256File(const std::string& utf8Path);

// Implementación portable sobre un búfer (la que usan Linux/macOS; también para los tests).
std::string sha256Hex(const void* data, size_t len);

// Cliente HTTPS mínimo: WinHTTP en Windows, libcurl en Linux/macOS.
#pragma once

#include <string>
#include <vector>

struct HttpResponse {
    int status = 0;     // 0 = error de red (ver `error`)
    std::string body;
    std::string error;
};

void httpInit();  // llamar una vez al arrancar
HttpResponse httpsGet(const std::string& host, const std::string& path, const std::vector<std::string>& headers);

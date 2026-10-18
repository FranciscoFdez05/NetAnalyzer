#include "core/http.h"

#include "core/common.h"  // NETANALYZER_VERSION

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>

namespace {
std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(size_t(n > 0 ? n - 1 : 0), L'\0');
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

struct Handle {
    HINTERNET h = nullptr;
    ~Handle() { if (h) WinHttpCloseHandle(h); }
};

std::string lastError(const char* what) { return std::string(what) + " falló (error " + std::to_string(GetLastError()) + ")"; }
}  // namespace

void httpInit() {}

HttpResponse httpsGet(const std::string& host, const std::string& path, const std::vector<std::string>& headers) {
    HttpResponse res;
    Handle session{WinHttpOpen(widen("NetAnalyzer/" NETANALYZER_VERSION).c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session.h) return {0, {}, lastError("WinHttpOpen")};
    WinHttpSetTimeouts(session.h, 10000, 10000, 20000, 20000);
    Handle conn{WinHttpConnect(session.h, widen(host).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0)};
    if (!conn.h) return {0, {}, lastError("WinHttpConnect")};
    Handle req{WinHttpOpenRequest(conn.h, L"GET", widen(path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)};
    if (!req.h) return {0, {}, lastError("WinHttpOpenRequest")};
    for (const auto& h : headers)
        WinHttpAddRequestHeaders(req.h, widen(h).c_str(), DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr))
        return {0, {}, lastError("Conexión HTTPS")};
    DWORD code = 0, size = sizeof code;
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &code, &size, WINHTTP_NO_HEADER_INDEX);
    res.status = int(code);
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req.h, &avail) || avail == 0) break;
        const size_t old = res.body.size();
        res.body.resize(old + avail);
        DWORD read = 0;
        if (!WinHttpReadData(req.h, res.body.data() + old, avail, &read)) break;
        res.body.resize(old + read);
        if (res.body.size() > 8 * 1024 * 1024) break;  // límite de seguridad
    }
    return res;
}

#else
#include <curl/curl.h>

namespace {
size_t onData(char* ptr, size_t size, size_t n, void* user) {
    auto* body = static_cast<std::string*>(user);
    if (body->size() > 8 * 1024 * 1024) return 0;  // límite de seguridad
    body->append(ptr, size * n);
    return size * n;
}
}  // namespace

void httpInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }

HttpResponse httpsGet(const std::string& host, const std::string& path, const std::vector<std::string>& headers) {
    HttpResponse res;
    CURL* curl = curl_easy_init();
    if (!curl) return {0, {}, "curl_easy_init falló"};
    const std::string url = "https://" + host + path;
    curl_slist* list = nullptr;
    for (const auto& h : headers) list = curl_slist_append(list, h.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "NetAnalyzer/" NETANALYZER_VERSION);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, onData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res.body);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // obligatorio con varios hilos
    const CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        res.status = int(code);
    } else {
        res.error = curl_easy_strerror(rc);
    }
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return res;
}
#endif

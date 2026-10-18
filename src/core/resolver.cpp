#include "core/resolver.h"

#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

// getnameinfo puede tardar varios segundos y no se puede cancelar, así que los hilos van
// separados (detach) y el Resolver debe vivir hasta que termine el proceso (ver main.cpp).
Resolver::Resolver(int workers) {
    for (int i = 0; i < workers; ++i) std::thread([this] { worker(); }).detach();
#ifdef _WIN32
    std::thread([this] { dnsCacheLoop(); }).detach();
#endif
}

Resolver::~Resolver() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        stop_ = true;
        queue_.clear();
    }
    cv_.notify_all();
}

std::string Resolver::name(const IpAddr& ip) {
    if (ip.isUnspecified()) return {};
    std::lock_guard<std::mutex> lk(mutex_);
    if (auto it = dns_.find(ip); it != dns_.end()) return it->second;
    if (auto it = ptr_.find(ip); it != ptr_.end()) return it->second;
    if (enabled && pending_.insert(ip).second) {
        queue_.push_back(ip);
        cv_.notify_one();
    }
    return {};
}

void Resolver::worker() {
    for (;;) {
        IpAddr ip;
        {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [this] { return stop_ || !queue_.empty(); });
            if (stop_) return;
            ip = queue_.front();
            queue_.pop_front();
        }
        std::string result;
        const Scope scope = ipScope(ip);
        if (scope == Scope::Loopback) {
            result = "localhost";
        } else if (scope != Scope::Multicast && scope != Scope::None) {
            sockaddr_storage ss{};
            socklen_t len = 0;
            if (ip.family == 4) {
                auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
                sa->sin_family = AF_INET;
                std::memcpy(&sa->sin_addr, ip.b.data(), 4);
                len = sizeof(sockaddr_in);
            } else {
                auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
                sa->sin6_family = AF_INET6;
                std::memcpy(&sa->sin6_addr, ip.b.data(), 16);
                len = sizeof(sockaddr_in6);
            }
            char host[NI_MAXHOST] = {0};
            if (getnameinfo(reinterpret_cast<sockaddr*>(&ss), len, host, sizeof host, nullptr, 0, NI_NAMEREQD) == 0)
                result = host;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        ptr_[ip] = result;
        pending_.erase(ip);
        if (!result.empty()) ++generation_;
    }
}

#ifdef _WIN32
namespace {
// API no documentada de dnsapi.dll (la usa ipconfig /displaydns).
struct DnsCacheEntry {
    DnsCacheEntry* next;
    PWSTR name;
    unsigned short type;
    unsigned short dataLength;
    unsigned long flags;
};
using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DnsCacheEntry**);

std::string narrow(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(size_t(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}
}  // namespace

void Resolver::dnsCacheLoop() {
    HMODULE dll = LoadLibraryW(L"dnsapi.dll");
    auto getTable = dll ? reinterpret_cast<DnsGetCacheDataTableFn>(GetProcAddress(dll, "DnsGetCacheDataTable"))
                        : nullptr;
    if (!getTable) return;
    for (;;) {
        std::unordered_map<IpAddr, std::string, IpAddrHash> found;
        DnsCacheEntry* head = nullptr;
        if (getTable(&head) && head) {
            for (DnsCacheEntry* e = head; e;) {
                if (e->name && (e->type == DNS_TYPE_A || e->type == DNS_TYPE_AAAA)) {
                    PDNS_RECORD rec = nullptr;
                    // DNS_QUERY_NO_WIRE_QUERY: solo consulta la caché local, sin tráfico de red.
                    if (DnsQuery_W(e->name, e->type, DNS_QUERY_NO_WIRE_QUERY, nullptr, &rec, nullptr) == 0) {
                        const std::string entry = narrow(e->name);
                        for (PDNS_RECORD r = rec; r; r = r->pNext) {
                            if (r->wType == DNS_TYPE_A) found[IpAddr::fromV4(&r->Data.A.IpAddress)] = entry;
                            else if (r->wType == DNS_TYPE_AAAA) found[IpAddr::fromV6(&r->Data.AAAA.Ip6Address)] = entry;
                        }
                        DnsRecordListFree(rec, DnsFreeRecordList);
                    }
                }
                DnsCacheEntry* next = e->next;
                DnsFree(e->name, DnsFreeFlat);
                DnsFree(e, DnsFreeFlat);
                e = next;
            }
        }
        {
            std::unique_lock<std::mutex> lk(mutex_);
            // No se borran entradas viejas: la conexión puede seguir viva aunque el
            // registro haya caducado de la caché DNS.
            for (auto& [ip, n] : found) {
                auto& slot = dns_[ip];
                if (slot != n) {
                    slot = std::move(n);
                    ++generation_;
                }
            }
            if (cv_.wait_for(lk, std::chrono::seconds(10), [this] { return stop_; })) return;
        }
    }
}
#else
void Resolver::dnsCacheLoop() {}
#endif

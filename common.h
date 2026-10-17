// Tipos y utilidades compartidas por todos los módulos.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef NETANALYZER_VERSION  // lo define CMake a partir de project(VERSION ...)
#define NETANALYZER_VERSION "dev"
#endif

enum class Proto : uint8_t { TCP = 0, UDP = 1 };

inline const char* protoName(Proto p) { return p == Proto::TCP ? "TCP" : "UDP"; }

// Dirección IPv4/IPv6 en orden de red.
struct IpAddr {
    uint8_t family = 0;  // 0 = vacía, 4 = IPv4, 6 = IPv6
    std::array<uint8_t, 16> b{};

    static IpAddr fromV4(const void* p) { IpAddr a; a.family = 4; std::memcpy(a.b.data(), p, 4); return a; }
    static IpAddr fromV6(const void* p) { IpAddr a; a.family = 6; std::memcpy(a.b.data(), p, 16); return a; }

    bool isUnspecified() const;
    bool isV4Mapped() const;
    std::string str() const;

    bool operator==(const IpAddr& o) const { return family == o.family && b == o.b; }
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    bool operator<(const IpAddr& o) const { return family != o.family ? family < o.family : b < o.b; }
};

struct IpAddrHash {
    size_t operator()(const IpAddr& a) const noexcept {
        uint64_t h = 1469598103934665603ull ^ a.family;
        for (uint8_t x : a.b) h = (h ^ x) * 1099511628211ull;
        return static_cast<size_t>(h);
    }
};

enum class Scope : uint8_t { None, Loopback, Private, LinkLocal, Multicast, Public };
Scope ipScope(const IpAddr& a);
const char* scopeName(Scope s);

// Un socket tal como lo reporta el sistema operativo.
struct Conn {
    Proto proto = Proto::TCP;
    IpAddr laddr, raddr;
    uint16_t lport = 0, rport = 0;
    const char* status = "";  // siempre un literal estático ("ESTABLISHED", "LISTEN", ...)
    int pid = -1;
    std::string pname;
    std::string lstr, rstr;   // texto de las IPs, rellenado por finalize()

    bool hasRemote() const { return rport != 0 && !raddr.isUnspecified(); }
    void finalize() {
        lstr = laddr.str();
        rstr = hasRemote() ? raddr.str() : std::string();
    }
};

struct ConnKey {
    Proto proto;
    IpAddr l, r;
    uint16_t lp, rp;
    int pid;
    bool operator==(const ConnKey& o) const {
        return proto == o.proto && lp == o.lp && rp == o.rp && pid == o.pid && l == o.l && r == o.r;
    }
};

// En TCP la 4-tupla ya identifica el socket; el PID no entra en la clave porque puede cambiar
// (Windows pasa los TIME_WAIT al PID 0; en Linux el PID puede resolverse más tarde).
// En UDP sí entra: varios procesos pueden compartir el mismo puerto local (p. ej. mDNS).
inline ConnKey keyOf(const Conn& c) {
    return {c.proto, c.laddr, c.raddr, c.lport, c.rport, c.proto == Proto::UDP ? c.pid : 0};
}

struct ConnKeyHash {
    size_t operator()(const ConnKey& k) const noexcept {
        IpAddrHash ih;
        size_t h = ih(k.l) * 31 + ih(k.r);
        h = h * 31 + ((size_t(k.lp) << 16) | k.rp);
        h = h * 31 + size_t(uint32_t(k.pid));
        return h * 31 + size_t(k.proto);
    }
};

// ---- utilidades
double nowSeconds();  // segundos desde epoch (reloj de pared)
std::string fmtDuration(double seconds);  // negativo -> "—"
std::string fmtClock(double ts);
std::string fmtClockMs(double ts);
std::string fmtAddr(const std::string& ip, uint16_t port, bool v6);
const char* serviceName(uint16_t port, Proto p);
const char* connService(const Conn& c);
std::string baseDomain(const std::string& host);
std::string toLower(std::string s);

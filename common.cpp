#include "common.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

bool IpAddr::isUnspecified() const {
    if (family == 0) return true;
    const size_t n = family == 4 ? 4 : 16;
    for (size_t i = 0; i < n; ++i)
        if (b[i]) return false;
    return true;
}

bool IpAddr::isV4Mapped() const {
    if (family != 6) return false;
    for (int i = 0; i < 10; ++i)
        if (b[i]) return false;
    return b[10] == 0xff && b[11] == 0xff;
}

std::string IpAddr::str() const {
    char buf[64] = {0};
    if (family == 4) {
        inet_ntop(AF_INET, b.data(), buf, sizeof buf);
    } else if (family == 6) {
        if (isV4Mapped()) return "::ffff:" + IpAddr::fromV4(b.data() + 12).str();
        inet_ntop(AF_INET6, b.data(), buf, sizeof buf);
    }
    return buf;
}

Scope ipScope(const IpAddr& a) {
    if (a.isUnspecified()) return Scope::None;
    const uint8_t* p = nullptr;
    if (a.family == 4) p = a.b.data();
    else if (a.isV4Mapped()) p = a.b.data() + 12;
    if (p) {
        if (p[0] == 127) return Scope::Loopback;
        if (p[0] == 10 || (p[0] == 172 && (p[1] & 0xf0) == 16) || (p[0] == 192 && p[1] == 168) ||
            (p[0] == 100 && (p[1] & 0xc0) == 64))
            return Scope::Private;
        if (p[0] == 169 && p[1] == 254) return Scope::LinkLocal;
        if (p[0] >= 224) return Scope::Multicast;  // multicast + broadcast/reservadas
        if (p[0] == 0) return Scope::None;
        return Scope::Public;
    }
    const auto& b = a.b;
    bool loop = b[15] == 1;
    for (int i = 0; i < 15 && loop; ++i) loop = b[i] == 0;
    if (loop) return Scope::Loopback;
    if (b[0] == 0xff) return Scope::Multicast;
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return Scope::LinkLocal;
    if ((b[0] & 0xfe) == 0xfc) return Scope::Private;
    return Scope::Public;
}

const char* scopeName(Scope s) {
    switch (s) {
        case Scope::Loopback: return "loopback";
        case Scope::Private: return "privada";
        case Scope::LinkLocal: return "link-local";
        case Scope::Multicast: return "multicast";
        case Scope::Public: return "pública";
        default: return "";
    }
}

double nowSeconds() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

std::string fmtDuration(double s) {
    char buf[32];
    if (s < 0) return "—";
    if (s < 1) std::snprintf(buf, sizeof buf, "%.0f ms", s * 1000);
    else if (s < 60) std::snprintf(buf, sizeof buf, "%.1f s", s);
    else if (s < 3600) std::snprintf(buf, sizeof buf, "%dm %02ds", int(s) / 60, int(s) % 60);
    else std::snprintf(buf, sizeof buf, "%dh %02dm", int(s) / 3600, (int(s) % 3600) / 60);
    return buf;
}

static std::tm localTm(double ts) {
    std::time_t t = static_cast<std::time_t>(ts);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    return tm;
}

std::string fmtClock(double ts) {
    if (ts <= 0) return "";
    std::tm tm = localTm(ts);
    char buf[16];
    std::strftime(buf, sizeof buf, "%H:%M:%S", &tm);
    return buf;
}

std::string fmtClockMs(double ts) {
    if (ts <= 0) return "";
    char buf[24];
    std::snprintf(buf, sizeof buf, "%s.%03d", fmtClock(ts).c_str(), int((ts - std::floor(ts)) * 1000));
    return buf;
}

std::string fmtAddr(const std::string& ip, uint16_t port, bool v6) {
    std::string host = ip.empty() ? "*" : ip;
    if (v6 && !ip.empty()) host = "[" + host + "]";
    return host + ":" + (port ? std::to_string(port) : std::string("*"));
}

const char* serviceName(uint16_t port, Proto p) {
    if (p == Proto::UDP && port == 443) return "quic";
    switch (port) {
        case 20: return "ftp-data";   case 21: return "ftp";        case 22: return "ssh";
        case 23: return "telnet";     case 25: return "smtp";       case 53: return "dns";
        case 67: case 68: return "dhcp";                            case 80: return "http";
        case 110: return "pop3";      case 123: return "ntp";       case 137: return "netbios-ns";
        case 138: return "netbios-dgm"; case 139: return "netbios"; case 143: return "imap";
        case 161: return "snmp";      case 389: return "ldap";      case 443: return "https";
        case 445: return "smb";       case 465: return "smtps";     case 500: return "ipsec";
        case 587: return "submission"; case 853: return "dns-tls";  case 993: return "imaps";
        case 995: return "pop3s";     case 1194: return "openvpn";  case 1900: return "ssdp";
        case 3306: return "mysql";    case 3389: return "rdp";      case 3478: return "stun";
        case 4500: return "ipsec-nat"; case 5060: return "sip";     case 5222: return "xmpp";
        case 5228: return "google-push"; case 5353: return "mdns";  case 5355: return "llmnr";
        case 5432: return "postgres"; case 5900: return "vnc";      case 6379: return "redis";
        case 8080: return "http-alt"; case 8443: return "https-alt"; case 27017: return "mongodb";
        case 51820: return "wireguard";
        default: return "";
    }
}

const char* connService(const Conn& c) {
    return serviceName(c.hasRemote() ? c.rport : c.lport, c.proto);
}

std::string baseDomain(const std::string& host) {
    if (host.empty() || std::isdigit(static_cast<unsigned char>(host.back())) ||
        host.find(':') != std::string::npos)
        return host;
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (i > start) parts.push_back(host.substr(start, i - start));
            start = i + 1;
        }
    }
    if (parts.size() < 2) return host;
    static const char* secondLevel[] = {"co", "com", "net", "org", "gov", "edu", "ac", "gob", "mil", "ne", "or"};
    size_t keep = 2;
    if (parts.size() >= 3 && parts.back().size() == 2) {
        for (const char* s : secondLevel)
            if (parts[parts.size() - 2] == s) keep = 3;
    }
    std::string out;
    for (size_t i = parts.size() - keep; i < parts.size(); ++i) {
        if (!out.empty()) out += '.';
        out += parts[i];
    }
    return out;
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

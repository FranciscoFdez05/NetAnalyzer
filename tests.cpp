// Tests de NetAnalyzer (sin dependencias ni red). Se ejecutan con:  ctest --test-dir build -C Release
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "collector.h"
#include "common.h"
#include "reputation.h"
#include "sha256.h"
#include "tracker.h"
#include "virustotal.h"

static int g_checks = 0, g_failures = 0;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        ++g_checks;                                                                   \
        if (!(cond)) {                                                                \
            ++g_failures;                                                             \
            std::cout << "  FALLO " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; \
        }                                                                             \
    } while (0)

#define CHECK_EQ(a, b)                                                                              \
    do {                                                                                            \
        ++g_checks;                                                                                 \
        const auto va_ = (a);                                                                       \
        const auto vb_ = (b);                                                                       \
        if (!(va_ == vb_)) {                                                                        \
            ++g_failures;                                                                           \
            std::cout << "  FALLO " << __FILE__ << ":" << __LINE__ << "  " #a " == " #b "\n"        \
                      << "        obtenido: '" << va_ << "'  esperado: '" << vb_ << "'\n";          \
        }                                                                                           \
    } while (0)

static IpAddr ip(const char* s) {
    uint8_t b[16] = {0};
    if (inet_pton(AF_INET, s, b) == 1) return IpAddr::fromV4(b);
    inet_pton(AF_INET6, s, b);
    return IpAddr::fromV6(b);
}

static Conn mk(Proto p, const char* l, uint16_t lp, const char* r, uint16_t rp, const char* st, int pid,
               const char* name) {
    Conn c;
    c.proto = p;
    c.laddr = ip(l);
    c.lport = lp;
    c.raddr = ip(r);
    c.rport = rp;
    c.status = st;
    c.pid = pid;
    c.pname = name;
    c.finalize();
    return c;
}

// ------------------------------------------------------------------ common

static void testCommon() {
    std::cout << "common\n";
    CHECK_EQ(ip("192.168.1.10").str(), std::string("192.168.1.10"));
    CHECK_EQ(ip("2001:db8::1").str(), std::string("2001:db8::1"));
    CHECK_EQ(ip("::ffff:10.0.0.1").str(), std::string("::ffff:10.0.0.1"));
    CHECK(ip("0.0.0.0").isUnspecified());
    CHECK(ip("::").isUnspecified());
    CHECK(IpAddr().isUnspecified());
    CHECK(!ip("1.1.1.1").isUnspecified());
    CHECK(ip("::ffff:1.2.3.4").isV4Mapped());

    CHECK(ipScope(ip("127.0.0.1")) == Scope::Loopback);
    CHECK(ipScope(ip("::1")) == Scope::Loopback);
    CHECK(ipScope(ip("10.1.2.3")) == Scope::Private);
    CHECK(ipScope(ip("172.16.0.1")) == Scope::Private);
    CHECK(ipScope(ip("172.31.255.255")) == Scope::Private);
    CHECK(ipScope(ip("172.32.0.1")) == Scope::Public);
    CHECK(ipScope(ip("192.168.0.1")) == Scope::Private);
    CHECK(ipScope(ip("100.64.0.1")) == Scope::Private);  // CGNAT
    CHECK(ipScope(ip("169.254.1.1")) == Scope::LinkLocal);
    CHECK(ipScope(ip("224.0.0.251")) == Scope::Multicast);
    CHECK(ipScope(ip("8.8.8.8")) == Scope::Public);
    CHECK(ipScope(ip("fe80::1")) == Scope::LinkLocal);
    CHECK(ipScope(ip("fd12:3456::1")) == Scope::Private);
    CHECK(ipScope(ip("ff02::fb")) == Scope::Multicast);
    CHECK(ipScope(ip("2001:4860:4860::8888")) == Scope::Public);
    CHECK(ipScope(ip("::ffff:10.0.0.1")) == Scope::Private);
    CHECK(ipScope(ip("0.0.0.0")) == Scope::None);

    CHECK_EQ(fmtDuration(-1), std::string("—"));
    CHECK_EQ(fmtDuration(0.25), std::string("250 ms"));
    CHECK_EQ(fmtDuration(5), std::string("5.0 s"));
    CHECK_EQ(fmtDuration(125), std::string("2m 05s"));
    CHECK_EQ(fmtDuration(3700), std::string("1h 01m"));
    CHECK_EQ(fmtAddr("1.2.3.4", 443, false), std::string("1.2.3.4:443"));
    CHECK_EQ(fmtAddr("::1", 80, true), std::string("[::1]:80"));
    CHECK_EQ(fmtAddr("", 0, false), std::string("*:*"));

    CHECK_EQ(std::string(serviceName(443, Proto::TCP)), std::string("https"));
    CHECK_EQ(std::string(serviceName(443, Proto::UDP)), std::string("quic"));
    CHECK_EQ(std::string(serviceName(53, Proto::UDP)), std::string("dns"));
    CHECK_EQ(std::string(serviceName(50000, Proto::TCP)), std::string(""));

    CHECK_EQ(baseDomain("lhr25s34-in-f14.1e100.net"), std::string("1e100.net"));
    CHECK_EQ(baseDomain("www.bbc.co.uk"), std::string("bbc.co.uk"));
    CHECK_EQ(baseDomain("static.example.com.ar"), std::string("example.com.ar"));
    CHECK_EQ(baseDomain("localhost"), std::string("localhost"));
    CHECK_EQ(baseDomain("1.2.3.4"), std::string("1.2.3.4"));
    CHECK_EQ(toLower("VivAldi.EXE"), std::string("vivaldi.exe"));

    // TCP: el PID no forma parte de la clave (Windows lo cambia a 0 en TIME_WAIT); UDP: sí.
    const Conn a = mk(Proto::TCP, "10.0.0.2", 5000, "1.1.1.1", 443, "ESTABLISHED", 100, "x");
    Conn b = a;
    b.pid = 0;
    CHECK(keyOf(a) == keyOf(b));
    CHECK(ConnKeyHash()(keyOf(a)) == ConnKeyHash()(keyOf(b)));
    Conn u1 = mk(Proto::UDP, "0.0.0.0", 5353, "0.0.0.0", 0, "", 10, "a");
    Conn u2 = u1;
    u2.pid = 11;
    CHECK(!(keyOf(u1) == keyOf(u2)));
    CHECK(!u1.hasRemote());
    CHECK(a.hasRemote());
}

// ------------------------------------------------------------------ sha256

static void testSha256() {
    std::cout << "sha256\n";
    // Vectores oficiales FIPS 180-4 (implementación portable: la de Linux/macOS).
    CHECK_EQ(sha256Hex("", 0), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256Hex("abc", 3), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char* m56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CHECK_EQ(sha256Hex(m56, std::strlen(m56)),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    const std::string million(1000000, 'a');
    CHECK_EQ(sha256Hex(million.data(), million.size()),
             std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

    // sha256File (BCrypt en Windows) debe coincidir con la portable.
    const auto path = std::filesystem::temp_directory_path() / "netanalyzer_test_sha.bin";
    { std::ofstream(path, std::ios::binary) << million; }
    CHECK_EQ(sha256File(path.u8string()), sha256Hex(million.data(), million.size()));
    std::filesystem::remove(path);
    CHECK_EQ(sha256File("/no/existe/netanalyzer.exe"), std::string(""));
}

// ------------------------------------------------------------------ tracker

static const ConnEvent* lastEvent(const Tracker& t) { return t.events.empty() ? nullptr : &t.events.back(); }

static void testTracker() {
    std::cout << "tracker\n";
    Tracker t;
    std::vector<Conn> s1 = {mk(Proto::TCP, "10.0.0.2", 50000, "1.1.1.1", 443, "ESTABLISHED", 100, "app.exe"),
                            mk(Proto::TCP, "0.0.0.0", 80, "0.0.0.0", 0, "LISTEN", 200, "server.exe")};
    // 1) Lo que ya existía al arrancar no genera eventos.
    CHECK_EQ(t.update(s1, 1000.0), 0);
    CHECK_EQ(t.live.size(), size_t(2));
    CHECK_EQ(t.totalOpens, uint64_t(2));
    CHECK(t.live.begin()->second.baseline);
    CHECK_EQ(t.hosts.size(), size_t(1));  // solo la que tiene destino remoto
    CHECK_EQ(t.procs[200].listening, 1);

    // 2) Conexión nueva al mismo host: evento de apertura, resaltada como nueva.
    auto s2 = s1;
    s2.push_back(mk(Proto::TCP, "10.0.0.2", 50001, "1.1.1.1", 443, "ESTABLISHED", 100, "app.exe"));
    CHECK_EQ(t.update(s2, 1001.0), 1);
    const ConnEvent* ev = lastEvent(t);
    CHECK(ev && ev->open);
    CHECK(ev && ev->interval < 0);  // primera apertura observada hacia ese host
    const HostStats& h = t.hosts.at(ip("1.1.1.1"));
    CHECK_EQ(h.total, 2);
    CHECK_EQ(h.active, 2);
    CHECK(t.live.at(keyOf(s2[2])).st == LiveConn::St::New);

    // 3) Otra apertura 3 s después: intervalo de 3 s.
    auto s3 = s2;
    s3.push_back(mk(Proto::TCP, "10.0.0.2", 50002, "1.1.1.1", 443, "ESTABLISHED", 100, "app.exe"));
    CHECK_EQ(t.update(s3, 1004.0), 1);
    CHECK(lastEvent(t)->interval > 2.99 && lastEvent(t)->interval < 3.01);
    CHECK(h.avgInterval() > 2.99 && h.avgInterval() < 3.01);
    CHECK(t.live.at(keyOf(s2[2])).st == LiveConn::St::Active);  // pasó el tiempo de resaltado

    // 4) Dos aperturas en el mismo muestreo: la segunda es "simultánea", sin intervalo de 0.
    auto s4 = s3;
    s4.push_back(mk(Proto::TCP, "10.0.0.2", 50003, "1.1.1.1", 443, "ESTABLISHED", 100, "app.exe"));
    s4.push_back(mk(Proto::TCP, "10.0.0.2", 50004, "1.1.1.1", 443, "ESTABLISHED", 100, "app.exe"));
    CHECK_EQ(t.update(s4, 1006.0), 2);
    CHECK(lastEvent(t)->burst);
    CHECK_EQ(h.intervals.size(), size_t(2));  // 3 s y 2 s; la simultánea no añade intervalo
    CHECK(h.minInterval > 1.99 && h.minInterval < 2.01);
    CHECK_EQ(h.ratePerMin(1006.0), 4);

    // 5) Windows pasa la conexión a TIME_WAIT con PID 0: no es cierre+apertura y conserva el dueño.
    auto s5 = s4;
    s5[2].status = "TIME_WAIT";
    s5[2].pid = 0;
    s5[2].pname = "System Idle";
    CHECK_EQ(t.update(s5, 1007.0), 0);
    CHECK_EQ(t.live.at(keyOf(s5[2])).c.pid, 100);
    CHECK_EQ(std::string(t.live.at(keyOf(s5[2])).c.status), std::string("TIME_WAIT"));
    CHECK(h.procs.count("System Idle") == 0);

    // 6) Desaparece: evento de cierre con su duración, visible en rojo y luego eliminada.
    auto s6 = s5;
    s6.erase(s6.begin() + 2);
    CHECK_EQ(t.update(s6, 1008.0), 1);
    CHECK(!lastEvent(t)->open);
    CHECK(lastEvent(t)->duration > 6.99 && lastEvent(t)->duration < 7.01);
    CHECK(t.live.at(keyOf(s5[2])).st == LiveConn::St::Closed);
    CHECK_EQ(t.hosts.at(ip("1.1.1.1")).active, 4);
    t.update(s6, 1008.0 + t.linger + 0.1);
    CHECK(t.live.count(keyOf(s5[2])) == 0);

    // 7) Reaparece la misma 4-tupla tras cerrarse: cuenta como conexión nueva.
    CHECK_EQ(t.update(s5, 1020.0), 1);
    CHECK(lastEvent(t)->open);

    // 8) Duplicados en la misma instantánea no cuentan dos veces.
    Tracker d;
    std::vector<Conn> dup = {s1[0], s1[0]};
    d.update(dup, 1.0);
    CHECK_EQ(d.live.size(), size_t(1));
    CHECK_EQ(d.totalOpens, uint64_t(1));

    // 9) Reinicio.
    t.reset();
    CHECK(t.live.empty() && t.hosts.empty() && t.events.empty() && t.totalOpens == 0);
}

// ------------------------------------------------------------------ veredictos

static void testVerdicts() {
    std::cout << "veredictos\n";
    VtResult v;
    CHECK_EQ(v.label(), std::string(""));
    CHECK_EQ(v.severity(), -1);
    v.st = VtResult::St::Done;
    v.harmless = 60;
    v.undetected = 10;
    CHECK_EQ(v.label(), std::string("0/70"));
    CHECK_EQ(std::string(v.verdict()), std::string("limpio"));
    v.malicious = 1;
    CHECK_EQ(v.severity(), 1);
    v.malicious = 3;
    CHECK_EQ(v.severity(), 2);
    CHECK_EQ(v.label(), std::string("3/73"));
    VtResult nf;
    nf.st = VtResult::St::NotFound;
    CHECK_EQ(nf.label(), std::string("desconocido"));
    CHECK(v.sortKey() > nf.sortKey());

    RepResult r;
    CHECK_EQ(r.label(), std::string(""));
    r.active = true;
    CHECK_EQ(r.label(), std::string("cargando"));
    r.listsReady = true;
    r.severity = 0;
    CHECK_EQ(r.label(), std::string("sin reportes"));
    r.severity = 1;
    r.tor = true;
    r.lists = "Tor";
    CHECK_EQ(r.label(), std::string("Tor"));
    r.lists = "Tor, CINS Army (atacantes)";
    CHECK_EQ(r.label(), std::string("sospechoso"));
    r.severity = 2;
    CHECK_EQ(r.label(), std::string("malicioso"));
}

// ------------------------------------------------------------------ listas negras

struct ReputationTest {
    static void run() {
        std::cout << "listas negras\n";
        Reputation::List l;
        Reputation::parseInto(l, "# comentario\n"
                                 "; otro comentario\n"
                                 "1.2.3.4\n"
                                 "  5.6.7.8   # con comentario al final\n"
                                 "10.20.0.0/16\n"
                                 "10.20.128.0/17\n"  // solapada: se fusiona
                                 "9.9.9.9;SBL123\n"
                                 "{\"cidr\":\"203.0.113.0/24\",\"sblid\":\"SBL1\",\"rir\":\"apnic\"}\n"
                                 "{\"type\":\"metadata\",\"timestamp\":1}\n"
                                 "2001:db8:abcd::/48\n"
                                 "2001:db8:1::5\n"
                                 "esto-no-es-una-ip\n"
                                 "300.1.1.1\n"
                                 "\r\n");
        Reputation::finalize(l);
        CHECK_EQ(l.raw.size(), size_t(8));  // metadatos, texto e IPs inválidas se descartan
        CHECK_EQ(l.v4.size(), size_t(5));  // las dos /16 y /17 solapadas quedan en una
        CHECK(Reputation::contains(l, ip("1.2.3.4")));
        CHECK(!Reputation::contains(l, ip("1.2.3.5")));
        CHECK(Reputation::contains(l, ip("5.6.7.8")));
        CHECK(Reputation::contains(l, ip("9.9.9.9")));
        CHECK(Reputation::contains(l, ip("10.20.255.255")));
        CHECK(!Reputation::contains(l, ip("10.21.0.0")));
        CHECK(Reputation::contains(l, ip("203.0.113.77")));
        CHECK(!Reputation::contains(l, ip("203.0.114.1")));
        CHECK(Reputation::contains(l, ip("::ffff:1.2.3.4")));  // IPv4 mapeada en IPv6
        CHECK(Reputation::contains(l, ip("2001:db8:abcd:1234::1")));
        CHECK(!Reputation::contains(l, ip("2001:db8:abce::1")));
        CHECK(Reputation::contains(l, ip("2001:db8:1::5")));
        CHECK(!Reputation::contains(l, ip("2001:db8:1::6")));

        // Prefijos que no son múltiplo de 8 y extremos.
        Reputation::List e;
        Reputation::parseInto(e, "0.0.0.0/0\n2001:db8:8000::/33\n");
        Reputation::finalize(e);
        CHECK(Reputation::contains(e, ip("255.255.255.255")));
        CHECK(Reputation::contains(e, ip("2001:db8:ffff::1")));
        CHECK(!Reputation::contains(e, ip("2001:db8:7fff::1")));
        Reputation::List empty;
        CHECK(!Reputation::contains(empty, ip("1.1.1.1")));
    }
};

// ------------------------------------------------------------------ recolector (API real del SO)

static void testCollector() {
    std::cout << "recolector\n";
#ifdef _WIN32
    using sock_t = SOCKET;
    const sock_t bad = INVALID_SOCKET;
    const int myPid = int(GetCurrentProcessId());
#else
    using sock_t = int;
    const sock_t bad = -1;
    const int myPid = int(getpid());
#endif
    // Abre un socket en escucha propio y comprueba que el recolector lo ve con nuestro PID.
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != bad);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CHECK(bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
    CHECK(listen(s, 1) == 0);
    socklen_t len = sizeof addr;
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    const uint16_t port = ntohs(addr.sin_port);

    auto col = Collector::create();
    std::vector<Conn> conns;
    std::string err;
    CHECK(col->collect(conns, err));
    CHECK(err.empty());
    CHECK(conns.size() > 0);
    bool found = false;
    for (Conn& c : conns) {
        c.finalize();
        if (c.proto == Proto::TCP && c.lport == port && c.lstr == "127.0.0.1") {
            found = true;
            CHECK_EQ(c.pid, myPid);
            CHECK_EQ(std::string(c.status), std::string("LISTEN"));
            CHECK(!c.pname.empty());
        }
    }
    CHECK(found);
    const std::string path = processPath(myPid);
    CHECK(!path.empty());
    CHECK(path.find("netanalyzer_tests") != std::string::npos);
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    testCommon();
    testSha256();
    testTracker();
    testVerdicts();
    ReputationTest::run();
    testCollector();
    std::cout << "\n" << (g_checks - g_failures) << "/" << g_checks << " comprobaciones correctas\n";
    return g_failures == 0 ? 0 : 1;
}

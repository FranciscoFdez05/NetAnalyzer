#include "reputation.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "collector.h"
#include "http.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#else
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#endif

namespace {

constexpr double kRefreshEvery = 6 * 3600.0;

// Listas públicas descargables sin registro. Severidad: 2 = malicioso, 1 = sospechoso.
struct SourceDef { const char* id; const char* name; const char* url; int severity; };
const SourceDef kSources[] = {
    {"feodo", "Feodo Tracker (botnets)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 2},
    {"drop4", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json", 2},
    {"drop6", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v6.json", 2},
    {"ipsum", "IPsum (3+ listas negras)", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", 2},
    {"et", "Emerging Threats (comprometidas)", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 1},
    {"cins", "CINS Army (atacantes)", "https://cinsscore.com/list/ci-badguys.txt", 1},
    {"bde", "blocklist.de (atacantes)", "https://lists.blocklist.de/lists/all.txt", 1},
    {"tor", "Tor", "https://check.torproject.org/torbulkexitlist", 1},
};

uint32_t v4Value(const uint8_t* b) {
    return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
}

// Consulta DNS de tipo TXT; devuelve la primera cadena.
bool dnsTxt(const std::string& name, std::string& out) {
#ifdef _WIN32
    DNS_RECORDA* rec = nullptr;
    if (DnsQuery_A(name.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, nullptr, reinterpret_cast<PDNS_RECORD*>(&rec),
                   nullptr) != 0)
        return false;
    bool ok = false;
    for (DNS_RECORDA* r = rec; r && !ok; r = r->pNext) {
        if (r->wType == DNS_TYPE_TEXT && r->Data.TXT.dwStringCount > 0 && r->Data.TXT.pStringArray[0]) {
            out = r->Data.TXT.pStringArray[0];
            ok = true;
        }
    }
    DnsRecordListFree(reinterpret_cast<PDNS_RECORD>(rec), DnsFreeRecordList);
    return ok;
#else
    unsigned char buf[4096];
    const int n = res_query(name.c_str(), ns_c_in, ns_t_txt, buf, sizeof buf);
    if (n <= 0) return false;
    ns_msg msg;
    if (ns_initparse(buf, n, &msg) < 0) return false;
    for (int i = 0; i < ns_msg_count(msg, ns_s_an); ++i) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0 || ns_rr_type(rr) != ns_t_txt || ns_rr_rdlen(rr) < 1) continue;
        const unsigned char* rd = ns_rr_rdata(rr);
        const int len = std::min<int>(rd[0], ns_rr_rdlen(rr) - 1);
        out.assign(reinterpret_cast<const char*>(rd + 1), size_t(len));
        return true;
    }
    return false;
#endif
}

std::vector<std::string> splitBar(const std::string& s) {
    std::vector<std::string> v;
    std::stringstream ss(s);
    std::string f;
    while (std::getline(ss, f, '|')) {
        const size_t a = f.find_first_not_of(' '), b = f.find_last_not_of(' ');
        v.push_back(a == std::string::npos ? std::string() : f.substr(a, b - a + 1));
    }
    return v;
}

// Nombre DNS de Team Cymru para la IP: "4.3.2.1.origin.asn.cymru.com" / nibbles + "origin6".
std::string cymruName(const IpAddr& ip) {
    char buf[160];
    if (ip.family == 4 || ip.isV4Mapped()) {
        const uint8_t* b = ip.family == 4 ? ip.b.data() : ip.b.data() + 12;
        std::snprintf(buf, sizeof buf, "%u.%u.%u.%u.origin.asn.cymru.com", b[3], b[2], b[1], b[0]);
        return buf;
    }
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (int i = 15; i >= 0; --i) {
        s += hex[ip.b[size_t(i)] & 0xf];
        s += '.';
        s += hex[ip.b[size_t(i)] >> 4];
        s += '.';
    }
    return s + "origin6.asn.cymru.com";
}

std::string cachePathFor(const std::string& ini) {
    const auto slash = ini.find_last_of("/\\");
    return (slash == std::string::npos ? std::string() : ini.substr(0, slash + 1)) + "netanalyzer_listas.txt";
}

}  // namespace

// ------------------------------------------------------------------ RepResult

std::string RepResult::label() const {
    if (!active) return "";
    if (!listsReady) return "cargando";
    switch (severity) {
        case 2: return "malicioso";
        case 1: return tor && lists == "Tor" ? "Tor" : "sospechoso";
        case 0: return "sin reportes";
        default: return "";
    }
}

int RepResult::sortKey() const {
    if (!active) return 0;
    if (!listsReady) return 1;
    return 2 + severity;
}

// ------------------------------------------------------------------ Reputation

// Igual que Resolver y VirusTotal: hilos separados y el objeto vive hasta que termina el proceso.
Reputation::Reputation() : cachePath_(cachePathFor(configFilePath())) {
    std::thread([this] { listsLoop(); }).detach();
    std::thread([this] { asnLoop(); }).detach();
}

void Reputation::setEnabled(bool enabled) {
    enabled_ = enabled;
    cv_.notify_all();
    ++generation_;
}

void Reputation::refreshNow() {
    refreshRequested_ = true;
    cv_.notify_all();
}

Reputation::Status Reputation::status() const {
    std::lock_guard<std::mutex> lk(mutex_);
    Status s;
    if (published_) {
        for (const List& l : *published_) {
            if (l.updated <= 0) continue;
            ++s.lists;
            s.entries += l.v4.size() + l.v6.size();
            s.updated = std::max(s.updated, l.updated);
        }
    }
    s.downloading = downloading_;
    s.error = error_;
    return s;
}

RepResult Reputation::lookup(const IpAddr& ip) {
    RepResult r;
    if (!enabled_ || ipScope(ip) != Scope::Public) return r;
    r.active = true;
    std::shared_ptr<const std::vector<List>> lists;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        lists = published_;
        auto it = asnCache_.find(ip);
        if (it != asnCache_.end()) {
            r.asn = it->second.asn;
            r.org = it->second.org;
            r.country = it->second.country;
        } else if (asnPending_.insert(ip).second) {
            asnQueue_.push_back(ip);
            cv_.notify_all();
        }
    }
    if (!lists) return r;
    bool any = false;
    for (const List& l : *lists) any |= l.updated > 0;
    if (!any) return r;
    r.listsReady = true;
    r.severity = 0;
    for (const List& l : *lists) {
        if (!contains(l, ip)) continue;
        if (r.lists.find(l.name) == std::string::npos) {
            if (!r.lists.empty()) r.lists += ", ";
            r.lists += l.name;
        }
        r.severity = std::max(r.severity, l.severity);
        if (l.id == "tor") r.tor = true;
    }
    return r;
}

bool Reputation::contains(const List& l, const IpAddr& ip) {
    if (ip.family == 4 || ip.isV4Mapped()) {
        const uint32_t val = v4Value(ip.family == 4 ? ip.b.data() : ip.b.data() + 12);
        auto it = std::upper_bound(l.v4.begin(), l.v4.end(), val,
                                   [](uint32_t v, const V4Range& rg) { return v < rg.lo; });
        return it != l.v4.begin() && std::prev(it)->hi >= val;
    }
    for (const V6Net& n : l.v6) {
        int bits = n.len;
        size_t i = 0;
        for (; bits >= 8; bits -= 8, ++i)
            if (ip.b[i] != n.net[i]) break;
        if (bits >= 8) continue;  // algún byte completo no coincide
        const uint8_t mask = uint8_t(0xff << (8 - bits));
        if (bits == 0 || (ip.b[i] & mask) == (n.net[i] & mask)) return true;
    }
    return false;
}

void Reputation::parseInto(List& list, const std::string& text) {
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        std::string token;
        if (const size_t c = line.find("\"cidr\":\""); c != std::string::npos) {  // Spamhaus (JSON por línea)
            const size_t end = line.find('"', c + 8);
            if (end != std::string::npos) token = line.substr(c + 8, end - c - 8);
        } else {
            const size_t a = line.find_first_not_of(" \t\r");
            if (a == std::string::npos || line[a] == '#' || line[a] == ';') continue;
            const size_t b = line.find_first_of(" \t\r,;", a);
            token = line.substr(a, b == std::string::npos ? std::string::npos : b - a);
        }
        if (token.empty()) continue;
        const size_t slash = token.find('/');
        const std::string addr = token.substr(0, slash);
        int len = slash == std::string::npos ? -1 : std::atoi(token.c_str() + slash + 1);
        uint8_t b[16];
        if (inet_pton(AF_INET, addr.c_str(), b) == 1) {
            if (len < 0 || len > 32) len = 32;
            const uint32_t v = v4Value(b);
            const uint32_t mask = len == 0 ? 0 : 0xffffffffu << (32 - len);
            list.v4.push_back({v & mask, (v & mask) | ~mask});
            list.raw.push_back(token);
        } else if (inet_pton(AF_INET6, addr.c_str(), b) == 1) {
            if (len < 0 || len > 128) len = 128;
            V6Net n;
            std::copy(b, b + 16, n.net.begin());
            n.len = len;
            list.v6.push_back(n);
            list.raw.push_back(token);
        }
    }
}

void Reputation::finalize(List& list) {
    std::sort(list.v4.begin(), list.v4.end(), [](const V4Range& a, const V4Range& b) { return a.lo < b.lo; });
    std::vector<V4Range> merged;
    for (const V4Range& r : list.v4) {
        if (!merged.empty() && r.lo <= merged.back().hi + 1ull) merged.back().hi = std::max(merged.back().hi, r.hi);
        else merged.push_back(r);
    }
    list.v4.swap(merged);
}

void Reputation::publish() {
    auto copy = std::make_shared<std::vector<List>>();
    for (const List& l : lists_) {
        List c = l;
        c.raw.clear();  // la copia de consulta no necesita el texto original
        copy->push_back(std::move(c));
    }
    {
        std::lock_guard<std::mutex> lk(mutex_);
        published_ = std::move(copy);
    }
    ++generation_;
}

void Reputation::loadCache() {
    std::ifstream f(std::filesystem::u8path(cachePath_));
    std::string line, text;
    List* cur = nullptr;
    auto flush = [&] {
        if (cur) {
            parseInto(*cur, text);
            finalize(*cur);
        }
        text.clear();
    };
    while (std::getline(f, line)) {
        if (line.compare(0, 6, "#list\t") == 0) {
            flush();
            std::stringstream ss(line.substr(6));
            std::string id, ts;
            std::getline(ss, id, '\t');
            std::getline(ss, ts, '\t');
            cur = nullptr;
            for (List& l : lists_)
                if (l.id == id) cur = &l;
            if (cur) {
                cur->updated = std::atof(ts.c_str());
                cur->v4.clear();
                cur->v6.clear();
                cur->raw.clear();
            }
        } else if (cur) {
            text += line;
            text += '\n';
        }
    }
    flush();
}

void Reputation::saveCache() const {
    std::ofstream f(std::filesystem::u8path(cachePath_), std::ios::trunc);
    if (!f) return;
    for (const List& l : lists_) {
        if (l.updated <= 0) continue;
        f << "#list\t" << l.id << '\t' << std::fixed << l.updated << '\n';
        for (const std::string& e : l.raw) f << e << '\n';
    }
}

void Reputation::listsLoop() {
    for (const SourceDef& s : kSources) {
        List l;
        l.id = s.id;
        l.name = s.name;
        l.severity = s.severity;
        lists_.push_back(std::move(l));
    }
    loadCache();  // arranque instantáneo con las listas de la última vez
    publish();

    for (;;) {
        if (enabled_) {
            const bool force = refreshRequested_.exchange(false);
            bool changed = false;
            std::string errors;
            for (size_t i = 0; i < lists_.size(); ++i) {
                List& l = lists_[i];
                if (!force && nowSeconds() - l.updated < kRefreshEvery) continue;
                {
                    std::lock_guard<std::mutex> lk(mutex_);
                    downloading_ = true;
                }
                const std::string url = kSources[i].url;
                const size_t hostStart = url.find("://") + 3;
                const size_t pathStart = url.find('/', hostStart);
                const HttpResponse res = httpsGet(url.substr(hostStart, pathStart - hostStart), url.substr(pathStart),
                                                  {"accept: text/plain, application/json"});
                if (res.status == 200 && !res.body.empty()) {
                    List fresh;
                    fresh.id = l.id;
                    fresh.name = l.name;
                    fresh.severity = l.severity;
                    parseInto(fresh, res.body);
                    finalize(fresh);
                    if (!fresh.raw.empty()) {
                        fresh.updated = nowSeconds();
                        l = std::move(fresh);
                        changed = true;
                        continue;
                    }
                }
                if (!errors.empty()) errors += ", ";
                errors += l.name;
            }
            if (changed) {
                publish();
                saveCache();
            }
            std::lock_guard<std::mutex> lk(mutex_);
            downloading_ = false;
            error_ = errors.empty() ? std::string() : "No se pudo actualizar: " + errors;
        }
        // Revisa cada 10 min si toca refrescar (o antes si se pide).
        std::unique_lock<std::mutex> lk(mutex_);
        cv_.wait_for(lk, std::chrono::minutes(10), [this] { return refreshRequested_.load(); });
    }
}

void Reputation::asnLoop() {
    std::unique_lock<std::mutex> lk(mutex_);
    for (;;) {
        cv_.wait(lk, [this] { return enabled_ && !asnQueue_.empty(); });
        const IpAddr ip = asnQueue_.front();
        asnQueue_.pop_front();
        lk.unlock();

        Asn info;
        std::string txt;
        if (dnsTxt(cymruName(ip), txt)) {
            // "15169 | 8.8.8.0/24 | US | arin | 2023-12-28" (puede traer varios AS: se usa el primero)
            const auto f = splitBar(txt);
            if (!f.empty()) {
                info.asn = f[0].substr(0, f[0].find(' '));
                if (f.size() > 2) info.country = f[2];
            }
            if (!info.asn.empty()) {
                std::string name;
                {
                    std::lock_guard<std::mutex> g(mutex_);
                    auto it = asnNames_.find(info.asn);
                    if (it != asnNames_.end()) name = it->second;
                }
                // "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
                if (name.empty() && dnsTxt("AS" + info.asn + ".asn.cymru.com", txt)) {
                    const auto g = splitBar(txt);
                    if (g.size() > 4) name = g[4];
                    std::lock_guard<std::mutex> lg(mutex_);
                    asnNames_[info.asn] = name;
                }
                info.org = name;
            }
        }

        lk.lock();
        asnCache_[ip] = std::move(info);
        asnPending_.erase(ip);
        ++generation_;
    }
}

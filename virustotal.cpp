#include "virustotal.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>

#include "collector.h"
#include "http.h"
#include "sha256.h"

namespace {

constexpr double kIpTtl = 24 * 3600.0;
constexpr double kFileTtl = 7 * 24 * 3600.0;
constexpr double kErrorRetry = 10 * 60.0;
const char* kHost = "www.virustotal.com";

int today() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    return (tm.tm_year + 1900) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday;
}

std::string clean(std::string s) {
    for (char& c : s)
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    return s;
}

std::string cachePathFor(const std::string& ini) {
    const auto slash = ini.find_last_of("/\\");
    return (slash == std::string::npos ? std::string() : ini.substr(0, slash + 1)) + "netanalyzer_virustotal.tsv";
}

}  // namespace

// ------------------------------------------------------------------ VtResult

int VtResult::severity() const {
    if (st != St::Done) return -1;
    if (malicious >= 3) return 2;  // varios motores coinciden: muy probablemente malicioso
    if (malicious > 0 || suspicious > 0) return 1;
    return 0;
}

std::string VtResult::label() const {
    switch (st) {
        case St::Queued: return "en cola";
        case St::NotFound: return "desconocido";
        case St::NoAccess: return "sin acceso";
        case St::Error: return "error";
        case St::Done: return std::to_string(malicious) + "/" + std::to_string(total());
        default: return "";
    }
}

const char* VtResult::verdict() const {
    switch (severity()) {
        case 2: return "malicioso";
        case 1: return "sospechoso";
        case 0: return "limpio";
        default: return "";
    }
}

int VtResult::sortKey() const {
    switch (st) {
        case St::Done: return 100 + malicious * 1000 + suspicious;
        case St::NotFound: return 50;
        case St::Queued: return 10;
        case St::Error: return 5;
        case St::NoAccess: return 2;
        default: return 0;
    }
}

// ------------------------------------------------------------------ VirusTotal

// Igual que el Resolver: el hilo puede estar dentro de una petición HTTPS al salir,
// así que va separado y el objeto vive hasta el final del proceso (ver main.cpp).
VirusTotal::VirusTotal() : cachePath_(cachePathFor(configFilePath())) {
    load();
    std::thread([this] { run(); }).detach();
}

void VirusTotal::configure(bool enabled, const std::string& apiKey, int perMinute, int perDay) {
    std::string key = apiKey;
    key.erase(std::remove_if(key.begin(), key.end(), [](char c) { return c == ' ' || c == '\t'; }), key.end());
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (key != apiKey_) {
            keyInvalid_ = false;
            error_.clear();
        }
        enabled_ = enabled;
        apiKey_ = key;
        perMinute_ = std::max(1, perMinute);
        perDay_ = std::max(1, perDay);
    }
    cv_.notify_all();
    ++generation_;
}

bool VirusTotal::fresh(const std::string& key, const VtResult& r) const {
    const double age = nowSeconds() - r.ts;
    if (r.st == VtResult::St::Error) return age < kErrorRetry;
    return age < (key.compare(0, 3, "ip:") == 0 ? kIpTtl : kFileTtl);
}

void VirusTotal::enqueueNet(const std::string& key, bool front) {
    if (inNet_.count(key)) {
        if (!front) return;
        netQueue_.erase(std::remove(netQueue_.begin(), netQueue_.end(), key), netQueue_.end());
    }
    inNet_.insert(key);
    if (front) netQueue_.push_front(key);
    else netQueue_.push_back(key);
    cv_.notify_all();
}

VtResult VirusTotal::ip(const IpAddr& addr, const std::string& ipStr) {
    if (ipScope(addr) != Scope::Public) return {};
    const std::string key = "ip:" + ipStr;
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = results_.find(key);
    if (it != results_.end() && (!enabled_ || fresh(key, it->second))) return it->second;
    if (!enabled_) return {};
    enqueueNet(key, false);
    if (it != results_.end()) return it->second;  // dato caducado: se muestra mientras se renueva
    VtResult r;
    r.st = VtResult::St::Queued;
    return r;
}

VtResult VirusTotal::process(int pid, const std::string& name) {
    VtResult r;
#ifdef _WIN32
    if (pid <= 4) return r;  // System Idle / System: el núcleo, no hay ejecutable que comprobar
#else
    if (pid <= 0) return r;
#endif
    std::lock_guard<std::mutex> lk(mutex_);
    const ProcKey k{pid, name};
    auto it = procs_.find(k);
    if (it == procs_.end()) {
        if (!enabled_) return r;
        procs_[k] = ProcEntry{};
        procQueue_.push_back(k);
        cv_.notify_all();
        r.st = VtResult::St::Queued;
        return r;
    }
    const ProcEntry& e = it->second;
    if (!e.resolved) {
        r.st = enabled_ ? VtResult::St::Queued : VtResult::St::Off;
        return r;
    }
    if (e.sha.empty()) {
        r.st = VtResult::St::NoAccess;
        r.path = e.path;
        return r;
    }
    const std::string key = "file:" + e.sha;
    auto rit = results_.find(key);
    if (rit != results_.end()) {
        r = rit->second;
        if (enabled_ && !fresh(key, r)) enqueueNet(key, false);
    } else {
        r.st = enabled_ ? VtResult::St::Queued : VtResult::St::Off;
        if (enabled_) enqueueNet(key, false);
    }
    r.sha256 = e.sha;
    r.path = e.path;
    return r;
}

void VirusTotal::recheckIp(const std::string& ipStr) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!enabled_) return;
    results_.erase("ip:" + ipStr);
    enqueueNet("ip:" + ipStr, true);
    ++generation_;
}

void VirusTotal::recheckProcess(int pid, const std::string& name) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!enabled_) return;
    auto it = procs_.find({pid, name});
    if (it != procs_.end() && !it->second.sha.empty()) {
        results_.erase("file:" + it->second.sha);
        enqueueNet("file:" + it->second.sha, true);
    } else {
        procs_[{pid, name}] = ProcEntry{};
        procQueue_.push_front({pid, name});
        cv_.notify_all();
    }
    ++generation_;
}

void VirusTotal::clearCache() {
    std::lock_guard<std::mutex> lk(mutex_);
    results_.clear();
    save();
    ++generation_;
}

VirusTotal::Status VirusTotal::status() const {
    std::lock_guard<std::mutex> lk(mutex_);
    Status s;
    s.enabled = enabled_;
    s.queued = netQueue_.size() + procQueue_.size();
    s.usedToday = day_ == today() ? usedToday_ : 0;
    s.perDay = perDay_;
    s.error = error_;
    return s;
}

std::string VirusTotal::hashFor(const std::string& path) {
    std::error_code ec;
    const auto p = std::filesystem::u8path(path);
    const auto size = std::filesystem::file_size(p, ec);
    if (ec) return {};
    const auto mtime = std::filesystem::last_write_time(p, ec).time_since_epoch().count();
    const std::string key = path + "|" + std::to_string(size) + "|" + std::to_string(mtime);
    {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = hashCache_.find(key);
        if (it != hashCache_.end()) return it->second;
    }
    std::string sha = sha256File(path);  // lo caro: fuera del mutex
    if (!sha.empty()) {
        std::lock_guard<std::mutex> lk(mutex_);
        hashCache_[key] = sha;
        hashesDirty_ = true;
    }
    return sha;
}

void VirusTotal::rollDay() {
    const int d = today();
    if (d != day_) {
        day_ = d;
        usedToday_ = 0;
    }
}

void VirusTotal::run() {
    std::unique_lock<std::mutex> lk(mutex_);
    for (;;) {
        // 1) Procesos pendientes: ruta + SHA-256 (local, sin red ni límite de ritmo).
        if (enabled_ && !procQueue_.empty()) {
            const ProcKey k = procQueue_.front();
            procQueue_.pop_front();
            lk.unlock();
            const std::string path = processPath(k.first);
            const std::string sha = path.empty() ? std::string() : hashFor(path);
            lk.lock();
            ProcEntry& e = procs_[k];
            e.path = path;
            e.sha = sha;
            e.resolved = true;
            if (!sha.empty()) {
                const std::string key = "file:" + sha;
                auto it = results_.find(key);
                if (it == results_.end() || !fresh(key, it->second)) enqueueNet(key, false);
            }
            if (procQueue_.empty() && hashesDirty_) {  // lote terminado: guarda los hashes nuevos
                save();
                hashesDirty_ = false;
            }
            ++generation_;
            continue;
        }

        // 2) Consultas a VirusTotal respetando los límites.
        rollDay();
        bool canNet = enabled_ && !apiKey_.empty() && !keyInvalid_ && !netQueue_.empty();
        if (canNet && usedToday_ >= perDay_) {
            error_ = "Límite diario de consultas alcanzado (" + std::to_string(perDay_) + ")";
            canNet = false;
        }
        const double now = nowSeconds();
        if (canNet && now >= nextAllowed_) {
            const std::string key = netQueue_.front();
            netQueue_.pop_front();
            inNet_.erase(key);
            const std::string apiKey = apiKey_;
            nextAllowed_ = now + 60.0 / perMinute_;
            ++usedToday_;
            lk.unlock();

            const bool isIp = key.compare(0, 3, "ip:") == 0;
            const std::string path = isIp ? "/api/v3/ip_addresses/" + key.substr(3) : "/api/v3/files/" + key.substr(5);
            const HttpResponse res = httpsGet(kHost, path, {"x-apikey: " + apiKey, "accept: application/json"});
            VtResult r;
            r.ts = nowSeconds();
            std::string err;
            if (res.status == 200) {
                try {
                    const auto j = nlohmann::json::parse(res.body);
                    const auto& a = j.at("data").at("attributes");
                    if (a.contains("last_analysis_stats") && a["last_analysis_stats"].is_object()) {
                        const auto& s = a["last_analysis_stats"];
                        r.malicious = s.value("malicious", 0);
                        r.suspicious = s.value("suspicious", 0);
                        r.harmless = s.value("harmless", 0);
                        r.undetected = s.value("undetected", 0);
                    }
                    if (isIp) {
                        if (a.contains("as_owner") && a["as_owner"].is_string()) r.owner = clean(a["as_owner"]);
                        if (a.contains("country") && a["country"].is_string()) r.country = clean(a["country"]);
                    } else if (a.contains("meaningful_name") && a["meaningful_name"].is_string()) {
                        r.owner = clean(a["meaningful_name"]);
                    }
                    r.st = VtResult::St::Done;
                } catch (const std::exception& e) {
                    r.st = VtResult::St::Error;
                    err = std::string("Respuesta de VirusTotal no válida: ") + e.what();
                }
            } else if (res.status == 404) {
                r.st = VtResult::St::NotFound;  // VirusTotal nunca ha visto ese archivo
            } else {
                r.st = VtResult::St::Error;
            }

            lk.lock();
            if (res.status == 401 || res.status == 403) {
                keyInvalid_ = true;
                error_ = "VirusTotal rechazó la API key (" + std::to_string(res.status) + "). Revísala en ajustes.";
                enqueueNet(key, true);
            } else if (res.status == 429) {
                nextAllowed_ = nowSeconds() + 60;  // cuota superada: espera un minuto y reintenta
                error_ = "VirusTotal: cuota superada (429), reintentando en 1 min";
                enqueueNet(key, true);
            } else {
                if (res.status == 0) error_ = "Sin conexión con VirusTotal: " + res.error;
                else if (r.st == VtResult::St::Error && err.empty()) error_ = "VirusTotal respondió HTTP " + std::to_string(res.status);
                else if (!err.empty()) error_ = err;
                else error_.clear();
                results_[key] = r;
                save();
            }
            ++generation_;
            continue;
        }

        // 3) Esperar a que haya trabajo o a que toque la siguiente consulta.
        if (canNet) cv_.wait_for(lk, std::chrono::duration<double>(std::max(0.05, nextAllowed_ - now)));
        else cv_.wait_for(lk, std::chrono::seconds(30));
    }
}

// Formato: clave \t estado \t ts \t malicious \t suspicious \t harmless \t undetected \t owner \t country
// Además: "#quota \t día \t usadas" y "#hash \t ruta|tamaño|fecha \t sha256" (evita releer ejecutables).
void VirusTotal::load() {
    std::ifstream f(std::filesystem::u8path(cachePath_));
    std::string line;
    while (std::getline(f, line)) {
        std::vector<std::string> v;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, '\t')) v.push_back(field);
        try {
            if (v.size() >= 3 && v[0] == "#quota") {
                day_ = std::stoi(v[1]);
                usedToday_ = std::stoi(v[2]);
                continue;
            }
            if (v.size() >= 3 && v[0] == "#hash") {
                hashCache_[v[1]] = v[2];
                continue;
            }
            if (v.size() < 7) continue;
            VtResult r;
            r.st = v[1] == "found" ? VtResult::St::Done : VtResult::St::NotFound;
            r.ts = std::stod(v[2]);
            r.malicious = std::stoi(v[3]);
            r.suspicious = std::stoi(v[4]);
            r.harmless = std::stoi(v[5]);
            r.undetected = std::stoi(v[6]);
            if (v.size() > 7) r.owner = v[7];
            if (v.size() > 8) r.country = v[8];
            results_[v[0]] = r;
        } catch (const std::exception&) {
            // línea corrupta: se ignora
        }
    }
}

void VirusTotal::save() const {
    std::ofstream f(std::filesystem::u8path(cachePath_), std::ios::trunc);
    if (!f) return;
    f << "#quota\t" << day_ << '\t' << usedToday_ << '\n';
    for (const auto& [key, sha] : hashCache_) f << "#hash\t" << key << '\t' << sha << '\n';
    for (const auto& [key, r] : results_) {
        if (r.st != VtResult::St::Done && r.st != VtResult::St::NotFound) continue;
        f << key << '\t' << (r.st == VtResult::St::Done ? "found" : "unknown") << '\t' << std::fixed << r.ts << '\t'
          << r.malicious << '\t' << r.suspicious << '\t' << r.harmless << '\t' << r.undetected << '\t' << r.owner
          << '\t' << r.country << '\n';
    }
}

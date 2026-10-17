// Comprobación de IPs remotas y ejecutables contra VirusTotal (API v3), como Process Explorer.
//  - Solo se envían IPs públicas y hashes SHA-256: nunca se sube ningún archivo.
//  - Desactivado por defecto; requiere la API key (gratuita) del usuario.
//  - Cola con límite por minuto y por día, y caché en disco (IPs 24 h, archivos 7 días).
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "common.h"

struct VtResult {
    enum class St : uint8_t { Off, Queued, Done, NotFound, NoAccess, Error };
    St st = St::Off;
    int malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
    std::string owner;    // IP: organización (AS); archivo: nombre conocido en VirusTotal
    std::string country;  // solo IPs
    std::string sha256;   // solo procesos
    std::string path;     // solo procesos
    double ts = 0;        // cuándo se consultó

    int total() const { return malicious + suspicious + harmless + undetected; }
    int severity() const;         // -1 sin datos, 0 limpio, 1 sospechoso, 2 malicioso
    std::string label() const;    // "3/72", "en cola", "desconocido"...
    const char* verdict() const;  // "malicioso", "sospechoso", "limpio" o ""
    int sortKey() const;
};

class VirusTotal {
public:
    struct Status {
        bool enabled = false;
        size_t queued = 0;
        int usedToday = 0, perDay = 0;
        std::string error;
    };

    VirusTotal();

    void configure(bool enabled, const std::string& apiKey, int perMinute, int perDay);
    // Devuelven el estado actual y, si hace falta, encolan la consulta (no bloquean).
    VtResult ip(const IpAddr& ip, const std::string& ipStr);
    VtResult process(int pid, const std::string& name);
    void recheckIp(const std::string& ipStr);
    void recheckProcess(int pid, const std::string& name);
    void clearCache();
    Status status() const;
    uint64_t generation() const { return generation_; }

private:
    using ProcKey = std::pair<int, std::string>;
    struct ProcEntry {
        std::string path, sha;
        bool resolved = false;
    };

    void run();
    bool fresh(const std::string& key, const VtResult& r) const;
    void enqueueNet(const std::string& key, bool front);
    std::string hashFor(const std::string& path);
    void rollDay();
    void load();
    void save() const;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool enabled_ = false, keyInvalid_ = false;
    std::string apiKey_;
    int perMinute_ = 4, perDay_ = 500;

    std::map<ProcKey, ProcEntry> procs_;
    std::deque<ProcKey> procQueue_;
    std::unordered_map<std::string, VtResult> results_;  // "ip:<ip>" / "file:<sha256>"
    std::deque<std::string> netQueue_;
    std::unordered_set<std::string> inNet_;
    std::unordered_map<std::string, std::string> hashCache_;  // ruta|tamaño|fecha -> sha256 (persistente)
    bool hashesDirty_ = false;

    double nextAllowed_ = 0;
    int day_ = 0, usedToday_ = 0;
    std::string error_;
    std::string cachePath_;
    std::atomic<uint64_t> generation_{0};
};

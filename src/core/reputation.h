// Reputación de IPs sin API key ni límites:
//  - Listas negras públicas (abuse.ch, Spamhaus, IPsum, Emerging Threats, CINS, blocklist.de, Tor)
//    descargadas cada 6 h y consultadas en local: ninguna IP del usuario sale del equipo.
//  - Organización/AS de cada IP mediante consultas DNS a Team Cymru (como el DNS inverso).
#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/common.h"

struct RepResult {
    bool active = false;   // false: IP local o función desactivada
    bool listsReady = false;
    int severity = -1;     // -1 sin datos, 0 sin reportes, 1 sospechoso, 2 malicioso
    std::string lists;     // listas en las que aparece ("Feodo Tracker, IPsum")
    bool tor = false;
    std::string asn, org, country;

    std::string label() const;  // "malicioso", "sospechoso", "Tor", "sin reportes", "cargando"
    int sortKey() const;
};

class Reputation {
public:
    struct Status {
        int lists = 0;
        size_t entries = 0;
        double updated = 0;
        bool downloading = false;
        std::string error;
    };

    Reputation();

    void setEnabled(bool enabled);
    RepResult lookup(const IpAddr& ip);  // no bloquea; encola la consulta de organización
    void refreshNow();
    Status status() const;
    uint64_t generation() const { return generation_; }

private:
    struct V4Range { uint32_t lo, hi; };
    struct V6Net { std::array<uint8_t, 16> net; int len; };
    struct List {
        std::string id, name;
        int severity = 1;
        double updated = 0;
        std::vector<V4Range> v4;
        std::vector<V6Net> v6;
        std::vector<std::string> raw;  // entradas tal cual, para la caché en disco
    };
    struct Asn { std::string asn, org, country; };

    friend struct ReputationTest;  // tests.cpp: prueba el análisis de listas sin red

    void listsLoop();
    void asnLoop();
    static void parseInto(List& list, const std::string& text);
    static void finalize(List& list);
    static bool contains(const List& list, const IpAddr& ip);
    void publish();
    void loadCache();
    void saveCache() const;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> enabled_{true};
    std::atomic<bool> refreshRequested_{false};
    std::vector<List> lists_;                                   // solo el hilo de listas
    std::shared_ptr<const std::vector<List>> published_;        // copia inmutable para consultar
    std::unordered_map<IpAddr, Asn, IpAddrHash> asnCache_;
    std::unordered_map<std::string, std::string> asnNames_;     // "15169" -> "GOOGLE - Google LLC, US"
    std::deque<IpAddr> asnQueue_;
    std::unordered_set<IpAddr, IpAddrHash> asnPending_;
    bool downloading_ = false;
    std::string error_;
    std::string cachePath_;
    std::atomic<uint64_t> generation_{0};
};

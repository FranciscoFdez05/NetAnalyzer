// Convierte instantáneas sucesivas de sockets en eventos (apertura/cierre) y estadísticas.
// El "tiempo entre peticiones" de un host es el tiempo entre aperturas de conexiones
// nuevas hacia él; su resolución es el intervalo de muestreo.
#pragma once

#include <deque>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common.h"

struct LiveConn {
    enum class St : uint8_t { New, Active, Closed };
    Conn c;
    double firstSeen = 0, lastSeen = 0, closedAt = 0;
    St st = St::Active;
    bool baseline = false;  // ya existía cuando empezó la monitorización

    double age(double now) const {
        const double end = st == St::Closed ? closedAt : now;
        return end > firstSeen ? end - firstSeen : 0.0;
    }
};

struct ConnEvent {
    uint64_t id = 0;
    double ts = 0;
    bool open = true;
    Conn c;
    double duration = 0;    // cierres
    double interval = -1;   // aperturas: tiempo desde la apertura anterior al mismo host
    bool burst = false;     // abierta en el mismo muestreo que la anterior al mismo host
    bool baseline = false;
};

struct HostStats {
    IpAddr ip;
    std::string ipStr;
    Scope scope = Scope::None;
    int total = 0, active = 0, activeTcp = 0, activeUdp = 0;
    double firstSeen = 0, lastSeen = 0;
    std::set<std::string> procs;
    std::set<std::pair<int, int>> ports;  // (proto, puerto remoto)
    std::string procsStr, portsStr;
    std::deque<double> opens;      // instantes de apertura (máx. kMaxHistory)
    std::deque<double> intervals;  // intervalos entre aperturas (máx. kMaxHistory)
    double sumIntervals = 0, minInterval = -1, maxInterval = -1;
    std::deque<ConnEvent> events;  // últimos eventos de este host

    double avgInterval() const { return intervals.empty() ? -1 : sumIntervals / double(intervals.size()); }
    double lastInterval() const { return intervals.empty() ? -1 : intervals.back(); }
    int ratePerMin(double now) const;
};

struct ProcStats {
    int pid = -1;
    std::string name;
    int activeTcp = 0, activeUdp = 0, listening = 0, total = 0;
    std::unordered_set<IpAddr, IpAddrHash> hosts;
    double lastSeen = 0;
};

struct Sample {
    double ts;
    int newTcp, newUdp;
    double rateTcp, rateUdp;
    int activeTcp, activeUdp;
};

class Tracker {
public:
    static constexpr size_t kMaxHistory = 2000;
    static constexpr size_t kMaxHostEvents = 400;
    static constexpr size_t kMaxEvents = 5000;
    static constexpr size_t kMaxSamples = 3600;

    std::unordered_map<ConnKey, LiveConn, ConnKeyHash> live;
    std::unordered_map<IpAddr, HostStats, IpAddrHash> hosts;
    std::unordered_map<int, ProcStats> procs;
    std::deque<ConnEvent> events;
    std::deque<Sample> timeline;
    uint64_t totalOpens = 0;
    double linger = 4.0;     // segundos que una conexión cerrada sigue visible (en rojo)
    double highlight = 3.0;  // segundos que una conexión nueva se resalta (en verde)

    // Procesa una instantánea; devuelve el número de eventos generados.
    int update(std::vector<Conn>& conns, double now);
    void reset();

private:
    ProcStats& proc(const Conn& c);
    bool open(const Conn& c, double now, bool baseline);
    void close(const LiveConn& lc, double now);
    void pushEvent(ConnEvent&& ev, HostStats* h);
    void recount(double now);

    uint64_t nextId_ = 1;
    double lastTs_ = 0;
    bool baselineDone_ = false;
};

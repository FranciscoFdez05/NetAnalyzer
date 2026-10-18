#include "core/tracker.h"

#include <algorithm>

int HostStats::ratePerMin(double now) const {
    int n = 0;
    for (auto it = opens.rbegin(); it != opens.rend() && now - *it <= 60.0; ++it) ++n;
    return n;
}

void Tracker::reset() { *this = Tracker(); }

int Tracker::update(std::vector<Conn>& conns, double now) {
    const bool baseline = !baselineDone_;
    std::unordered_set<ConnKey, ConnKeyHash> seen;
    seen.reserve(conns.size() * 2);
    int newTcp = 0, newUdp = 0, nEvents = 0;

    for (Conn& c : conns) {
        ConnKey k = keyOf(c);
        if (!seen.insert(k).second) continue;  // duplicados (p. ej. sockets compartidos)
        auto it = live.find(k);
        if (it == live.end() || it->second.st == LiveConn::St::Closed) {
            LiveConn lc;
            lc.c = c;
            lc.firstSeen = lc.lastSeen = now;
            lc.st = baseline ? LiveConn::St::Active : LiveConn::St::New;
            lc.baseline = baseline;
            live[k] = std::move(lc);
            if (open(c, now, baseline)) {
                ++nEvents;
                (c.proto == Proto::TCP ? newTcp : newUdp)++;
            }
        } else {
            LiveConn& lc = it->second;
            lc.c.status = c.status;
            if (c.pid > 0 || lc.c.pid <= 0) {  // conserva el dueño original si pasa a PID 0 (TIME_WAIT)
                lc.c.pid = c.pid;
                if (!c.pname.empty()) lc.c.pname = c.pname;
            }
            lc.lastSeen = now;
            if (lc.st == LiveConn::St::New && now - lc.firstSeen >= highlight) lc.st = LiveConn::St::Active;
        }
    }

    for (auto it = live.begin(); it != live.end();) {
        LiveConn& lc = it->second;
        if (seen.count(it->first)) {
            ++it;
        } else if (lc.st != LiveConn::St::Closed) {
            lc.st = LiveConn::St::Closed;
            lc.closedAt = now;
            close(lc, now);
            ++nEvents;
            ++it;
        } else if (now - lc.closedAt >= linger) {
            it = live.erase(it);
        } else {
            ++it;
        }
    }

    recount(now);

    const double dt = lastTs_ > 0 ? now - lastTs_ : 0;
    Sample s{now, newTcp, newUdp, dt > 0 ? newTcp / dt : 0, dt > 0 ? newUdp / dt : 0, 0, 0};
    for (auto& [pid, p] : procs) {
        s.activeTcp += p.activeTcp;
        s.activeUdp += p.activeUdp;
    }
    timeline.push_back(s);
    if (timeline.size() > kMaxSamples) timeline.pop_front();
    lastTs_ = now;
    baselineDone_ = true;
    return nEvents;
}

ProcStats& Tracker::proc(const Conn& c) {
    ProcStats& p = procs[c.pid];
    p.pid = c.pid;
    if (!c.pname.empty()) p.name = c.pname;
    return p;
}

static std::string joinProcs(const std::set<std::string>& s) {
    std::string out;
    for (const auto& x : s) {
        if (!out.empty()) out += ", ";
        out += x;
    }
    return out;
}

static std::string joinPorts(const std::set<std::pair<int, int>>& s) {
    std::string out;
    int shown = 0;
    for (const auto& [proto, port] : s) {
        if (shown++ == 8) {
            out += ", ...";
            break;
        }
        if (!out.empty()) out += ", ";
        out += protoName(Proto(proto));
        out += ' ';
        out += std::to_string(port);
    }
    return out;
}

bool Tracker::open(const Conn& c, double now, bool baseline) {
    ProcStats& p = proc(c);
    ++p.total;
    p.lastSeen = now;
    ++totalOpens;
    HostStats* h = nullptr;
    ConnEvent ev;
    if (c.hasRemote()) {
        auto [it, inserted] = hosts.try_emplace(c.raddr);
        h = &it->second;
        if (inserted) {
            h->ip = c.raddr;
            h->ipStr = c.rstr;
            h->scope = ipScope(c.raddr);
            h->firstSeen = now;
        }
        ++h->total;
        h->lastSeen = now;
        // PID 0 en Windows = sockets en TIME_WAIT sin dueño: no es un proceso real.
        if (c.pid != 0 &&
            h->procs.insert(c.pname.empty() ? (c.pid > 0 ? std::to_string(c.pid) : "?") : c.pname).second)
            h->procsStr = joinProcs(h->procs);
        if (h->ports.insert({int(c.proto), c.rport}).second) h->portsStr = joinPorts(h->ports);
        p.hosts.insert(c.raddr);
        if (!baseline) {
            if (!h->opens.empty()) {
                const double gap = now - h->opens.back();
                if (gap > 0) {
                    ev.interval = gap;
                    h->intervals.push_back(gap);
                    h->sumIntervals += gap;
                    if (h->intervals.size() > kMaxHistory) {
                        h->sumIntervals -= h->intervals.front();
                        h->intervals.pop_front();
                    }
                    h->minInterval = h->minInterval < 0 ? gap : std::min(h->minInterval, gap);
                    h->maxInterval = std::max(h->maxInterval, gap);
                } else {
                    ev.burst = true;
                }
            }
            h->opens.push_back(now);
            if (h->opens.size() > kMaxHistory) h->opens.pop_front();
        }
    }
    if (baseline) return false;  // lo que ya existía al arrancar no es un evento
    ev.id = nextId_++;
    ev.ts = now;
    ev.open = true;
    ev.c = c;
    pushEvent(std::move(ev), h);
    return true;
}

void Tracker::close(const LiveConn& lc, double now) {
    ConnEvent ev;
    ev.id = nextId_++;
    ev.ts = now;
    ev.open = false;
    ev.c = lc.c;
    ev.duration = lc.age(now);
    ev.baseline = lc.baseline;
    HostStats* h = nullptr;
    if (lc.c.hasRemote()) {
        auto it = hosts.find(lc.c.raddr);
        if (it != hosts.end()) {
            h = &it->second;
            h->lastSeen = now;
        }
    }
    pushEvent(std::move(ev), h);
}

void Tracker::pushEvent(ConnEvent&& ev, HostStats* h) {
    if (h) {
        h->events.push_back(ev);
        if (h->events.size() > kMaxHostEvents) h->events.pop_front();
    }
    events.push_back(std::move(ev));
    if (events.size() > kMaxEvents) events.pop_front();
}

void Tracker::recount(double now) {
    for (auto& [ip, h] : hosts) h.active = h.activeTcp = h.activeUdp = 0;
    for (auto& [pid, p] : procs) p.activeTcp = p.activeUdp = p.listening = 0;
    for (auto& [k, lc] : live) {
        if (lc.st == LiveConn::St::Closed) continue;
        const Conn& c = lc.c;
        ProcStats& p = proc(c);
        p.lastSeen = now;
        (c.proto == Proto::TCP ? p.activeTcp : p.activeUdp)++;
        if (!c.hasRemote()) {
            ++p.listening;
            continue;
        }
        auto it = hosts.find(c.raddr);
        if (it == hosts.end()) continue;
        ++it->second.active;
        (c.proto == Proto::TCP ? it->second.activeTcp : it->second.activeUdp)++;
    }
}

// Enumeración de sockets con su proceso propietario, usando la API nativa de cada SO:
//   Windows: GetExtendedTcpTable / GetExtendedUdpTable (lo que usa Get-NetTCPConnection)
//   Linux:   /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd (lo que usa netstat -tunap)
//   macOS:   libproc proc_pidfdinfo (lo que usa lsof -i)
#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/common.h"

class Collector {
public:
    virtual ~Collector() = default;
    // Rellena `out` con todos los sockets TCP/UDP. Devuelve false y rellena `err` si falla.
    virtual bool collect(std::vector<Conn>& out, std::string& err) = 0;
    virtual const char* name() const = 0;

    static std::unique_ptr<Collector> create();  // implementado en collector_<so>.cpp
};

// ---- utilidades dependientes del SO (collector_<so>.cpp)
bool isElevated();
const char* privilegeHint();  // aviso a mostrar cuando no hay privilegios ("" si no hace falta)
bool killProcess(int pid, std::string& err);
std::string processPath(int pid);  // ruta completa del ejecutable ("" si no hay acceso)
void openInBrowser(const std::string& url);
std::string configFilePath();

struct Snapshot {
    std::vector<Conn> conns;
    double ts = 0;
    double ms = 0;
    std::string error;
};

// Hilo que consulta al SO periódicamente sin bloquear la interfaz.
class CollectorThread {
public:
    explicit CollectorThread(std::function<void()> onData);
    ~CollectorThread();

    void setInterval(double seconds);
    void setPaused(bool paused);
    bool paused() const { return paused_; }
    void refreshNow();
    bool take(Snapshot& out);  // true si había una instantánea nueva
    const char* sourceName() const { return collector_->name(); }

private:
    void run();

    std::unique_ptr<Collector> collector_;
    std::function<void()> onData_;
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
    bool wake_ = false;
    std::atomic<double> interval_{1.0};
    std::atomic<bool> paused_{false};
    Snapshot pending_;
    bool hasPending_ = false;
};

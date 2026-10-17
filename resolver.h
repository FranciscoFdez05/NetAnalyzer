// Resolución IP -> nombre sin bloquear la interfaz.
//  1. Windows: caché DNS del sistema (dominio que realmente pidió la aplicación).
//  2. Todos: DNS inverso (PTR) con un pool de hilos.
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common.h"

class Resolver {
public:
    explicit Resolver(int workers = 6);
    ~Resolver();

    // Nombre conocido ("" si aún no se sabe; en ese caso se encola la resolución).
    std::string name(const IpAddr& ip);
    // Cambia cada vez que se resuelve un nombre nuevo (para refrescar la vista).
    uint64_t generation() const { return generation_; }

    std::atomic<bool> enabled{true};

private:
    void worker();
    void dnsCacheLoop();

    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::deque<IpAddr> queue_;
    std::unordered_set<IpAddr, IpAddrHash> pending_;
    std::unordered_map<IpAddr, std::string, IpAddrHash> ptr_;
    std::unordered_map<IpAddr, std::string, IpAddrHash> dns_;
    std::atomic<uint64_t> generation_{0};
};

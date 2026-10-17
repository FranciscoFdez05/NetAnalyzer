#include "collector.h"

#include <chrono>

CollectorThread::CollectorThread(std::function<void()> onData)
    : collector_(Collector::create()), onData_(std::move(onData)) {
    thread_ = std::thread([this] { run(); });
}

CollectorThread::~CollectorThread() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void CollectorThread::setInterval(double seconds) {
    interval_ = seconds < 0.1 ? 0.1 : seconds;
    refreshNow();
}

void CollectorThread::setPaused(bool paused) {
    paused_ = paused;
    refreshNow();
}

void CollectorThread::refreshNow() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        wake_ = true;
    }
    cv_.notify_all();
}

bool CollectorThread::take(Snapshot& out) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!hasPending_) return false;
    out = std::move(pending_);
    pending_ = Snapshot{};
    hasPending_ = false;
    return true;
}

void CollectorThread::run() {
    using clock = std::chrono::steady_clock;
    std::vector<Conn> buf;
    for (;;) {
        const auto started = clock::now();
        if (!paused_) {
            Snapshot snap;
            buf.clear();
            if (!collector_->collect(buf, snap.error)) buf.clear();
            for (Conn& c : buf) c.finalize();
            snap.conns.swap(buf);
            snap.ts = nowSeconds();
            snap.ms = std::chrono::duration<double, std::milli>(clock::now() - started).count();
            {
                // Si la interfaz no recogió la anterior, se sustituye: siempre gana la más reciente.
                std::lock_guard<std::mutex> lk(mutex_);
                pending_ = std::move(snap);
                hasPending_ = true;
            }
            if (onData_) onData_();
        }
        std::unique_lock<std::mutex> lk(mutex_);
        const auto deadline = started + std::chrono::duration_cast<clock::duration>(
                                            std::chrono::duration<double>(interval_.load()));
        cv_.wait_until(lk, deadline, [this] { return stop_ || wake_; });
        wake_ = false;
        if (stop_) return;
    }
}

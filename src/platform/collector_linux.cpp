// Linux: lee /proc/net/{tcp,tcp6,udp,udp6} (la misma fuente que netstat -tunap / ss) y
// asocia cada inode de socket a su PID recorriendo /proc/<pid>/fd.
// Sin root solo se pueden asociar los procesos del propio usuario.
#include "core/collector.h"

#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

namespace {

const char* tcpState(unsigned s) {
    switch (s) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSED";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "?";
    }
}

// El kernel imprime cada palabra de 32 bits de la dirección en orden nativo.
bool parseHexAddr(const char* hex, size_t len, IpAddr& out) {
    if (len != 8 && len != 32) return false;
    uint8_t bytes[16];
    for (size_t w = 0; w < len / 8; ++w) {
        char word[9];
        std::memcpy(word, hex + w * 8, 8);
        word[8] = 0;
        uint32_t v = static_cast<uint32_t>(std::strtoul(word, nullptr, 16));
        std::memcpy(bytes + w * 4, &v, 4);
    }
    out = len == 8 ? IpAddr::fromV4(bytes) : IpAddr::fromV6(bytes);
    return true;
}

bool parseEndpoint(const char* tok, IpAddr& addr, uint16_t& port) {
    const char* colon = std::strchr(tok, ':');
    if (!colon || !parseHexAddr(tok, size_t(colon - tok), addr)) return false;
    port = static_cast<uint16_t>(std::strtoul(colon + 1, nullptr, 16));
    return true;
}

bool isDigits(const char* s) {
    if (!*s) return false;
    for (; *s; ++s)
        if (*s < '0' || *s > '9') return false;
    return true;
}

class LinuxCollector : public Collector {
public:
    const char* name() const override { return "/proc/net (netstat -tunap)"; }

    bool collect(std::vector<Conn>& out, std::string& err) override {
        inodes_.clear();
        bool ok = false;
        ok |= readTable("/proc/net/tcp", Proto::TCP, out);
        ok |= readTable("/proc/net/tcp6", Proto::TCP, out);
        ok |= readTable("/proc/net/udp", Proto::UDP, out);
        ok |= readTable("/proc/net/udp6", Proto::UDP, out);
        if (!ok) {
            err = "No se pudo leer /proc/net/*";
            return false;
        }
        mapInodesToPids();
        for (size_t i = 0; i < out.size(); ++i) {
            unsigned long ino = inodes_[i];
            if (!ino) continue;
            auto it = inodeToPid_.find(ino);
            if (it == inodeToPid_.end()) continue;
            out[i].pid = it->second;
            out[i].pname = processName(it->second);
        }
        return true;
    }

private:
    bool readTable(const char* path, Proto proto, std::vector<Conn>& out) {
        FILE* f = std::fopen(path, "r");
        if (!f) return false;
        char line[512];
        if (!std::fgets(line, sizeof line, f)) {  // cabecera
            std::fclose(f);
            return true;
        }
        while (std::fgets(line, sizeof line, f)) {
            char local[64], remote[64];
            unsigned state = 0;
            unsigned long inode = 0;
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
            if (std::sscanf(line, " %*d: %63s %63s %x %*s %*s %*s %*u %*u %lu", local, remote, &state,
                            &inode) != 4)
                continue;
            Conn c;
            c.proto = proto;
            if (!parseEndpoint(local, c.laddr, c.lport) || !parseEndpoint(remote, c.raddr, c.rport)) continue;
            if (proto == Proto::TCP) c.status = tcpState(state);
            else c.status = state == 0x01 ? "ESTABLISHED" : "";
            out.push_back(std::move(c));
            inodes_.push_back(inode);
        }
        std::fclose(f);
        return true;
    }

    // Recorre /proc/*/fd solo cuando aparecen inodes desconocidos (es la parte cara).
    void mapInodesToPids() {
        bool needScan = false;
        for (unsigned long ino : inodes_)
            if (ino && !inodeToPid_.count(ino) && !unresolved_.count(ino)) { needScan = true; break; }
        const double now = nowSeconds();
        if (now - lastFullScan_ > 30) {
            unresolved_.clear();  // reintenta los no resueltos de vez en cuando
            needScan = needScan || !inodes_.empty();
        }
        if (!needScan) return;
        lastFullScan_ = now;
        inodeToPid_.clear();
        DIR* proc = opendir("/proc");
        if (!proc) return;
        char path[64], target[64];
        while (dirent* pe = readdir(proc)) {
            if (!isDigits(pe->d_name)) continue;
            std::snprintf(path, sizeof path, "/proc/%s/fd", pe->d_name);
            DIR* fds = opendir(path);
            if (!fds) continue;  // sin permisos (otro usuario sin root)
            const int pid = std::atoi(pe->d_name);
            while (dirent* fe = readdir(fds)) {
                if (fe->d_name[0] == '.') continue;
                char fdpath[96];
                std::snprintf(fdpath, sizeof fdpath, "/proc/%s/fd/%s", pe->d_name, fe->d_name);
                ssize_t n = readlink(fdpath, target, sizeof target - 1);
                if (n <= 8) continue;
                target[n] = 0;
                if (std::strncmp(target, "socket:[", 8) == 0)
                    inodeToPid_[std::strtoul(target + 8, nullptr, 10)] = pid;
            }
            closedir(fds);
        }
        closedir(proc);
        for (unsigned long ino : inodes_)
            if (ino && !inodeToPid_.count(ino)) unresolved_.insert(ino);
    }

    const std::string& processName(int pid) {
        auto it = names_.find(pid);
        if (it != names_.end() && nowSeconds() - it->second.second < 20) return it->second.first;
        std::string name;
        std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
        std::getline(f, name);
        auto& slot = names_[pid];
        slot = {name, nowSeconds()};
        return slot.first;
    }

    std::vector<unsigned long> inodes_;  // paralelo a `out` en cada collect()
    std::unordered_map<unsigned long, int> inodeToPid_;
    std::unordered_set<unsigned long> unresolved_;
    std::unordered_map<int, std::pair<std::string, double>> names_;
    double lastFullScan_ = 0;
};

}  // namespace

std::unique_ptr<Collector> Collector::create() { return std::make_unique<LinuxCollector>(); }

bool isElevated() { return geteuid() == 0; }

const char* privilegeHint() {
    return isElevated() ? ""
                        : "Sin root solo se ven los procesos de tu usuario (sudo -E ./NetAnalyzer o setcap, ver README)";
}

bool killProcess(int pid, std::string& err) {
    if (::kill(pid, SIGTERM) == 0) return true;
    err = std::string("kill falló: ") + std::strerror(errno);
    return false;
}

std::string processPath(int pid) {
    if (pid <= 0) return {};
    char buf[4096];
    const std::string link = "/proc/" + std::to_string(pid) + "/exe";
    const ssize_t n = readlink(link.c_str(), buf, sizeof buf - 1);
    if (n <= 0) return {};
    buf[n] = 0;
    return buf;  // si el binario se borró termina en " (deleted)" y no se podrá leer
}

void openInBrowser(const std::string& url) {
    // Doble fork para no dejar procesos zombi.
    pid_t child = fork();
    if (child == 0) {
        if (fork() == 0) {
            execlp("xdg-open", "xdg-open", url.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        _exit(0);
    }
    if (child > 0) waitpid(child, nullptr, 0);
}

std::string configFilePath() {
    std::string dir;
    if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x) dir = x;
    else if (const char* h = std::getenv("HOME"); h && *h) dir = std::string(h) + "/.config";
    else return "netanalyzer.ini";
    mkdir(dir.c_str(), 0700);  // por si no existe; si ya existe no pasa nada
    return dir + "/netanalyzer.ini";
}

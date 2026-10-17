// macOS: recorre los descriptores de cada proceso con libproc (la misma API que usa
// lsof -i). Sin root solo se ven los procesos del propio usuario.
#include "collector.h"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace {

const char* tcpState(int s) {
    switch (s) {
        case TSI_S_CLOSED: return "CLOSED";
        case TSI_S_LISTEN: return "LISTEN";
        case TSI_S_SYN_SENT: return "SYN_SENT";
        case TSI_S_SYN_RECEIVED: return "SYN_RECV";
        case TSI_S_ESTABLISHED: return "ESTABLISHED";
        case TSI_S__CLOSE_WAIT: return "CLOSE_WAIT";
        case TSI_S_FIN_WAIT_1: return "FIN_WAIT1";
        case TSI_S_CLOSING: return "CLOSING";
        case TSI_S_LAST_ACK: return "LAST_ACK";
        case TSI_S_FIN_WAIT_2: return "FIN_WAIT2";
        case TSI_S_TIME_WAIT: return "TIME_WAIT";
        default: return "?";
    }
}

void fillAddrs(const in_sockinfo& in, Conn& c) {
    c.lport = ntohs(static_cast<uint16_t>(in.insi_lport));
    c.rport = ntohs(static_cast<uint16_t>(in.insi_fport));
    if (in.insi_vflag & INI_IPV4) {
        c.laddr = IpAddr::fromV4(&in.insi_laddr.ina_46.i46a_addr4);
        c.raddr = IpAddr::fromV4(&in.insi_faddr.ina_46.i46a_addr4);
    } else {
        c.laddr = IpAddr::fromV6(&in.insi_laddr.ina_6);
        c.raddr = IpAddr::fromV6(&in.insi_faddr.ina_6);
    }
}

class MacCollector : public Collector {
public:
    const char* name() const override { return "libproc (lsof -i)"; }

    bool collect(std::vector<Conn>& out, std::string& err) override {
        int bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
        if (bytes <= 0) {
            err = "proc_listpids falló";
            return false;
        }
        pids_.resize(size_t(bytes) / sizeof(pid_t) + 64);
        bytes = proc_listpids(PROC_ALL_PIDS, 0, pids_.data(), int(pids_.size() * sizeof(pid_t)));
        const size_t npids = bytes > 0 ? size_t(bytes) / sizeof(pid_t) : 0;

        for (size_t i = 0; i < npids; ++i) {
            const pid_t pid = pids_[i];
            if (pid <= 0) continue;
            int sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
            if (sz <= 0) continue;  // sin permisos o el proceso ya terminó
            fds_.resize(size_t(sz) / sizeof(proc_fdinfo) + 16);
            sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds_.data(), int(fds_.size() * sizeof(proc_fdinfo)));
            if (sz <= 0) continue;
            const size_t nfds = size_t(sz) / sizeof(proc_fdinfo);
            std::string pname;
            bool named = false;
            for (size_t f = 0; f < nfds; ++f) {
                if (fds_[f].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
                socket_fdinfo si{};
                if (proc_pidfdinfo(pid, fds_[f].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof si) < int(sizeof si))
                    continue;
                const auto& s = si.psi;
                if (s.soi_family != AF_INET && s.soi_family != AF_INET6) continue;
                Conn c;
                if (s.soi_kind == SOCKINFO_TCP) {
                    c.proto = Proto::TCP;
                    fillAddrs(s.soi_proto.pri_tcp.tcpsi_ini, c);
                    c.status = tcpState(s.soi_proto.pri_tcp.tcpsi_state);
                } else if (s.soi_kind == SOCKINFO_IN && s.soi_protocol == IPPROTO_UDP) {
                    c.proto = Proto::UDP;
                    fillAddrs(s.soi_proto.pri_in, c);
                    c.status = c.rport ? "ESTABLISHED" : "";
                } else {
                    continue;
                }
                if (!named) {
                    char buf[2 * MAXCOMLEN + 1] = {0};
                    proc_name(pid, buf, sizeof buf);
                    pname = buf;
                    named = true;
                }
                c.pid = pid;
                c.pname = pname;
                out.push_back(std::move(c));
            }
        }
        return true;
    }

private:
    std::vector<pid_t> pids_;
    std::vector<proc_fdinfo> fds_;
};

}  // namespace

std::unique_ptr<Collector> Collector::create() { return std::make_unique<MacCollector>(); }

bool isElevated() { return geteuid() == 0; }

const char* privilegeHint() {
    return isElevated() ? "" : "Sin root solo se ven los procesos de tu usuario (ejecuta: sudo ./NetAnalyzer)";
}

bool killProcess(int pid, std::string& err) {
    if (::kill(pid, SIGTERM) == 0) return true;
    err = std::string("kill falló: ") + std::strerror(errno);
    return false;
}

std::string processPath(int pid) {
    if (pid <= 0) return {};
    char buf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    return proc_pidpath(pid, buf, sizeof buf) > 0 ? std::string(buf) : std::string();
}

void openInBrowser(const std::string& url) {
    pid_t child = fork();
    if (child == 0) {
        if (fork() == 0) {
            execlp("open", "open", url.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        _exit(0);
    }
    if (child > 0) waitpid(child, nullptr, 0);
}

std::string configFilePath() {
    if (const char* h = std::getenv("HOME"); h && *h) return std::string(h) + "/Library/Preferences/netanalyzer.ini";
    return "netanalyzer.ini";
}

// Windows: GetExtendedTcpTable / GetExtendedUdpTable. No requiere administrador para ver
// todas las conexiones con su PID; los nombres salen de una instantánea Toolhelp32.
#include "collector.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <unordered_map>

namespace {

const char* tcpState(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECV";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "?";
    }
}

std::string narrow(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(size_t(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Llama a una función Get*Table creciendo el búfer hasta que quepa.
template <typename F>
bool fetchTable(F fn, std::vector<char>& buf) {
    for (int attempt = 0; attempt < 6; ++attempt) {
        DWORD size = static_cast<DWORD>(buf.size());
        DWORD r = fn(buf.empty() ? nullptr : buf.data(), &size);
        if (r == NO_ERROR) return true;
        if (r != ERROR_INSUFFICIENT_BUFFER) return false;
        buf.resize(size + 16 * 1024);
    }
    return false;
}

class WinCollector : public Collector {
public:
    const char* name() const override { return "GetExtendedTcpTable/UdpTable"; }

    bool collect(std::vector<Conn>& out, std::string& err) override {
        bool ok = false;
        if (fetchTable([](void* p, DWORD* s) {
                return GetExtendedTcpTable(p, s, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); }, buf_)) {
            ok = true;
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf_.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                Conn c;
                c.proto = Proto::TCP;
                c.laddr = IpAddr::fromV4(&r.dwLocalAddr);
                c.raddr = IpAddr::fromV4(&r.dwRemoteAddr);
                c.lport = ntohs(static_cast<u_short>(r.dwLocalPort));
                c.rport = ntohs(static_cast<u_short>(r.dwRemotePort));
                c.status = tcpState(r.dwState);
                c.pid = static_cast<int>(r.dwOwningPid);
                out.push_back(std::move(c));
            }
        }
        if (fetchTable([](void* p, DWORD* s) {
                return GetExtendedTcpTable(p, s, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); }, buf_)) {
            ok = true;
            auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf_.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                Conn c;
                c.proto = Proto::TCP;
                c.laddr = IpAddr::fromV6(r.ucLocalAddr);
                c.raddr = IpAddr::fromV6(r.ucRemoteAddr);
                c.lport = ntohs(static_cast<u_short>(r.dwLocalPort));
                c.rport = ntohs(static_cast<u_short>(r.dwRemotePort));
                c.status = tcpState(r.dwState);
                c.pid = static_cast<int>(r.dwOwningPid);
                out.push_back(std::move(c));
            }
        }
        if (fetchTable([](void* p, DWORD* s) {
                return GetExtendedUdpTable(p, s, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); }, buf_)) {
            ok = true;
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf_.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                Conn c;
                c.proto = Proto::UDP;
                c.laddr = IpAddr::fromV4(&r.dwLocalAddr);
                c.lport = ntohs(static_cast<u_short>(r.dwLocalPort));
                c.pid = static_cast<int>(r.dwOwningPid);
                out.push_back(std::move(c));
            }
        }
        if (fetchTable([](void* p, DWORD* s) {
                return GetExtendedUdpTable(p, s, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0); }, buf_)) {
            ok = true;
            auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf_.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                Conn c;
                c.proto = Proto::UDP;
                c.laddr = IpAddr::fromV6(r.ucLocalAddr);
                c.lport = ntohs(static_cast<u_short>(r.dwLocalPort));
                c.pid = static_cast<int>(r.dwOwningPid);
                out.push_back(std::move(c));
            }
        }
        if (!ok) {
            err = "GetExtendedTcpTable/UdpTable falló (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        resolveNames(out);
        return true;
    }

private:
    void resolveNames(std::vector<Conn>& conns) {
        const ULONGLONG now = GetTickCount64();
        bool missing = false;
        for (const Conn& c : conns)
            if (c.pid > 4 && !names_.count(c.pid)) { missing = true; break; }
        // Los PIDs se reutilizan: refresco completo cada 10 s aunque no falte ninguno.
        if (missing || now - lastSnapshot_ > 10000) {
            snapshotProcesses();
            lastSnapshot_ = now;
        }
        for (Conn& c : conns) {
            if (c.pid == 0) c.pname = "System Idle";
            else if (c.pid == 4) c.pname = "System";
            else if (auto it = names_.find(c.pid); it != names_.end()) c.pname = it->second;
        }
    }

    void snapshotProcesses() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        names_.clear();
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof pe;
        for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe))
            names_[static_cast<int>(pe.th32ProcessID)] = narrow(pe.szExeFile);
        CloseHandle(snap);
    }

    std::vector<char> buf_;
    std::unordered_map<int, std::string> names_;
    ULONGLONG lastSnapshot_ = 0;
};

}  // namespace

std::unique_ptr<Collector> Collector::create() { return std::make_unique<WinCollector>(); }

bool isElevated() { return IsUserAnAdmin() != FALSE; }

const char* privilegeHint() { return ""; }  // en Windows se ven todas las conexiones sin admin

bool killProcess(int pid, std::string& err) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        err = "No se pudo abrir el proceso (error " + std::to_string(GetLastError()) +
              "). Puede requerir ejecutar como administrador.";
        return false;
    }
    BOOL ok = TerminateProcess(h, 1);
    if (!ok) err = "TerminateProcess falló (error " + std::to_string(GetLastError()) + ")";
    CloseHandle(h);
    return ok != FALSE;
}

namespace {
// "\Device\HarddiskVolume3\Windows\x.exe" -> "C:\Windows\x.exe"
std::wstring ntPathToDos(const std::wstring& nt) {
    wchar_t drives[512];
    const DWORD n = GetLogicalDriveStringsW(512, drives);
    for (const wchar_t* d = drives; n && *d; d += wcslen(d) + 1) {
        const std::wstring letter(d, 2);  // "C:"
        wchar_t device[MAX_PATH];
        if (!QueryDosDeviceW(letter.c_str(), device, MAX_PATH)) continue;
        const std::wstring prefix = std::wstring(device) + L"\\";
        if (nt.compare(0, prefix.size(), prefix) == 0) return letter + L"\\" + nt.substr(prefix.size());
    }
    return {};
}

// Ruta de cualquier PID sin abrir el proceso (como Process Explorer): funciona también con
// servicios del sistema (svchost...) cuando no se es administrador.
std::wstring imagePathByPid(int pid) {
    struct UStr { USHORT Length, MaximumLength; PWSTR Buffer; };
    struct ProcessIdInfo { HANDLE ProcessId; UStr ImageName; };
    using NtQsi = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    static const auto query =
        reinterpret_cast<NtQsi>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!query) return {};
    std::vector<wchar_t> buf(32767);
    ProcessIdInfo info{};
    info.ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    info.ImageName.Buffer = buf.data();
    info.ImageName.MaximumLength = static_cast<USHORT>(buf.size() * sizeof(wchar_t));
    constexpr ULONG kSystemProcessIdInformation = 88;
    if (query(kSystemProcessIdInformation, &info, sizeof info, nullptr) < 0) return {};
    return ntPathToDos(std::wstring(info.ImageName.Buffer, info.ImageName.Length / sizeof(wchar_t)));
}
}  // namespace

std::string processPath(int pid) {
    if (pid <= 4) return {};  // System Idle / System no tienen ejecutable
    if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))) {
        std::vector<wchar_t> buf(32768);
        DWORD n = static_cast<DWORD>(buf.size());
        std::string out;
        if (QueryFullProcessImageNameW(h, 0, buf.data(), &n)) out = narrow(buf.data());
        CloseHandle(h);
        if (!out.empty()) return out;
    }
    const std::wstring path = imagePathByPid(pid);
    return path.empty() ? std::string() : narrow(path.c_str());
}

void openInBrowser(const std::string& url) {
    ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

std::string configFilePath() {
    char path[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path)))
        return std::string(path) + "\\NetAnalyzer.ini";
    return "NetAnalyzer.ini";
}

// Interfaz gráfica (Dear ImGui + ImPlot). La interfaz es dueña del Tracker: los datos
// llegan del hilo recolector y se procesan aquí, así no hace falta bloquear nada.
#pragma once

#include <string>
#include <vector>

#include "collector.h"
#include "reputation.h"
#include "resolver.h"
#include "tracker.h"
#include "virustotal.h"

struct ImFont;

class App {
public:
    struct Settings {
        float interval = 1.0f;
        bool tcp = true, udp = true;
        bool onlyEstablished = false;
        bool listening = false;    // sockets en escucha / UDP sin destino
        bool localhost = true;
        bool dns = true;
        bool hostsOnlyActive = false;
        bool groupByDomain = false;
        bool procsOnlyActive = true;
        int spanIndex = 1;         // ventana de las gráficas de actividad
        bool reputation = true;    // listas negras públicas + organización (sin API key)
        bool vtEnabled = false;    // VirusTotal (opt-in)
        char vtKey[128] = {};
        int vtPerMinute = 4;       // límites del plan gratuito
        int vtPerDay = 500;
    };

    App(CollectorThread& collector, Resolver& resolver, VirusTotal& vt, Reputation& rep);

    void poll();   // recoge datos nuevos (se llama también con la ventana minimizada)
    void frame();  // dibuja la interfaz completa
    void selectTab(int tab) { pendingTab_ = tab; }

    Settings settings;
    ImFont* fontBig = nullptr;
    float scale = 1.0f;

private:
    struct ConnRow { LiveConn* lc; std::string host, hay; VtResult vtIp, vtProc; RepResult rep; };
    struct HostRow { HostStats* h; std::string name, hay; VtResult vt; RepResult rep; };
    struct ProcRow { ProcStats* p; std::string hay; VtResult vt; };
    struct EventRow { const ConnEvent* e; std::string host; };
    struct SortState { int col; bool asc; bool dirty = true; };

    void registerSettings();
    void settingsChanged();
    void rebuildViews();
    void rebuildSeries();
    bool passConn(const Conn& c) const;
    bool matchFilter(const std::string& hay) const;
    void setFilter(const std::string& text);
    void parseFilter();
    void toast(const std::string& msg, bool error = false);
    void requestKill(int pid, const std::string& name);
    void exportCsv();
    double viewNow() const;
    bool vtActive() const { return settings.vtEnabled && settings.vtKey[0]; }
    // Flags para columnas de funciones opcionales: ocultas del todo mientras estén desactivadas.
    int vtColumnFlags() const;
    int repColumnFlags() const;
    int orgColumnFlags() const;  // organización/país: los da la reputación o VirusTotal

    void drawToolbar();
    void drawCards();
    void drawConnections();
    void drawHosts();
    void drawHostBars();
    void drawHostDetail();
    void drawProcesses();
    void drawActivity();
    void drawEventsTable(const char* id, const std::vector<EventRow>& rows, bool compact);
    void drawStatusBar();
    void drawModals();
    void connMenu(const Conn& c, const std::string& host, const VtResult& vtProc);
    void ipIntelMenu(const std::string& ip);
    void vtProcMenu(int pid, const std::string& name, const VtResult& vt);
    void drawVtSettings();
    void applyVtSettings();

    void sortConns();
    void sortHosts();
    void sortProcs();

    CollectorThread& collector_;
    Resolver& resolver_;
    VirusTotal& vt_;
    Reputation& rep_;
    Tracker tracker_;
    uint64_t lastVtGen_ = 0, lastRepGen_ = 0;
    int vtAlerts_ = 0, vtMalicious_ = 0;
    bool vtSettingsRequested_ = false;
    bool vtShowKey_ = false;

    char filter_[256] = {0};
    std::vector<std::string> include_, exclude_;

    std::vector<ConnRow> connRows_;
    std::vector<HostRow> hostRows_;
    std::vector<ProcRow> procRows_;
    std::vector<EventRow> eventRows_, hostEventRows_;
    SortState connSort_, hostSort_, procSort_;

    // series para las gráficas
    std::vector<double> tsSeries_, rateTcp_, rateUdp_, actTcp_, actUdp_;
    std::vector<float> sparkTcp_, sparkUdp_, sparkNew_;
    std::vector<std::string> barLabels_;
    std::vector<double> barValues_;
    std::vector<IpAddr> barHosts_;  // vacío si se agrupa por dominio

    bool dirty_ = true;
    bool firstFrame_ = true;
    uint64_t lastNameGen_ = 0;
    double lastNameRebuild_ = 0;
    double lastPollTs_ = 0;
    double lastPollMs_ = 0;
    size_t lastSockets_ = 0;
    std::string lastError_;

    IpAddr selHost_;
    bool hasSelHost_ = false;
    IpAddr detailHost_;  // host del panel de detalle: el seleccionado o, si no hay, el más activo
    bool hasDetail_ = false;
    ConnKey selConn_{};
    bool hasSelConn_ = false;
    int currentTab_ = 0;
    int pendingTab_ = -1;
    bool focusFilter_ = false;

    int killPid_ = -1;
    std::string killName_;
    bool killRequested_ = false;

    std::string toast_;
    bool toastError_ = false;
    double toastUntil_ = 0;
};

#include "app/app.h"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>

#include "imgui.h"
#include "imgui_internal.h"
#include "implot.h"

namespace {

const ImVec4 kTcp(0.35f, 0.62f, 1.00f, 1.0f);
const ImVec4 kUdp(0.95f, 0.66f, 0.30f, 1.0f);
const ImVec4 kGreen(0.27f, 0.75f, 0.50f, 1.0f);
const ImVec4 kRed(0.94f, 0.38f, 0.38f, 1.0f);
const ImVec4 kMuted(0.50f, 0.54f, 0.61f, 1.0f);
const ImVec4 kText(0.89f, 0.90f, 0.92f, 1.0f);
const ImVec4 kHeaderText(0.66f, 0.69f, 0.75f, 1.0f);
const ImVec4 kLink(0.60f, 0.74f, 0.96f, 1.0f);
const ImVec4 kAccent(0.30f, 0.55f, 1.00f, 1.0f);
const ImVec4 kViolet(0.62f, 0.52f, 0.98f, 1.0f);
const ImU32 kRowNew = IM_COL32(63, 185, 120, 26);
const ImU32 kRowClosed = IM_COL32(240, 95, 95, 26);

// Iconos de Segoe Fluent Icons / MDL2 Assets (solo se usan si la fuente está disponible).
#define ICON_PAUSE "\xEE\x9D\xA9"
#define ICON_PLAY "\xEE\x9D\xA8"
#define ICON_REFRESH "\xEE\x9C\xAC"
#define ICON_SEARCH "\xEE\x9C\xA1"
#define ICON_SHIELD "\xEE\xA8\x98"
#define ICON_RESET "\xEE\x9D\xB7"
#define ICON_EXPORT "\xEE\xA2\x96"

const double kSpans[] = {60, 300, 900, 3600};
const char* kSpanNames[] = {"1 min", "5 min", "15 min", "1 hora"};

// Estado de dibujo compartido por los helpers (lo fija App::frame() en cada frame).
float gScale = 1.0f;
ImFont* gBold = nullptr;
ImFont* gSmall = nullptr;
bool gIcons = false;

const ImVec4& protoColor(Proto p) { return p == Proto::TCP ? kTcp : kUdp; }

ImVec4 withAlpha(const ImVec4& c, float a) { return ImVec4(c.x, c.y, c.z, a); }
float fontPx(const ImFont* f) { return f->FontSize * ImGui::GetIO().FontGlobalScale; }

std::string withIcon(const char* glyph, const char* text) {
    return gIcons ? std::string(glyph) + "  " + text : std::string(text);
}

// Interruptor en forma de "chip": punto de color + texto, resaltado cuando está activo.
bool chip(const char* label, bool* v, const ImVec4& dot) {
    const ImGuiStyle& st = ImGui::GetStyle();
    const char* end = ImGui::FindRenderedTextEnd(label);
    const ImVec2 ts = ImGui::CalcTextSize(label, end);
    const float h = ImGui::GetFrameHeight();
    const float dotW = 14 * gScale;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const ImVec2 size(ts.x + dotW + st.FramePadding.x * 2, h);
    const bool pressed = ImGui::InvisibleButton(label, size);
    if (pressed) *v = !*v;
    const bool hov = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 q(p.x + size.x, p.y + size.y);
    const ImU32 bg = *v ? ImGui::GetColorU32(withAlpha(kAccent, hov ? 0.20f : 0.13f))
                        : ImGui::GetColorU32(ImVec4(1, 1, 1, hov ? 0.05f : 0.0f));
    const ImU32 border = *v ? ImGui::GetColorU32(withAlpha(kAccent, 0.45f)) : ImGui::GetColorU32(ImGuiCol_Border);
    dl->AddRectFilled(p, q, bg, h * 0.5f);
    dl->AddRect(p, q, border, h * 0.5f);
    const float cx = p.x + st.FramePadding.x + 3.5f * gScale;
    dl->AddCircleFilled(ImVec2(cx, p.y + h * 0.5f), 3.5f * gScale,
                        ImGui::GetColorU32(*v ? dot : withAlpha(kMuted, 0.5f)));
    dl->AddText(ImVec2(p.x + st.FramePadding.x + dotW, p.y + (h - ts.y) * 0.5f),
                ImGui::GetColorU32(*v ? ImGuiCol_Text : ImGuiCol_TextDisabled), label, end);
    return pressed;
}

// Separador vertical fino entre grupos de controles de una misma fila.
void vSeparator() {
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float h = ImGui::GetFrameHeight();
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x + 6 * gScale, p.y + 5 * gScale),
                                        ImVec2(p.x + 6 * gScale, p.y + h - 5 * gScale),
                                        ImGui::GetColorU32(ImGuiCol_Border));
    ImGui::Dummy(ImVec2(12 * gScale, h));
}

// Etiqueta compacta con fondo tintado (protocolo, tipo de evento...).
void pill(const char* text, const ImVec4& col) {
    ImFont* f = gSmall ? gSmall : ImGui::GetFont();
    const float fs = fontPx(f);
    const ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, text);
    const float lh = ImGui::GetTextLineHeight();
    const float padX = 6 * gScale, rh = std::min(lh, fs + 4 * gScale);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const ImVec2 a(p.x, p.y + (lh - rh) * 0.5f), b(p.x + ts.x + padX * 2, a.y + rh);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(a, b, ImGui::GetColorU32(withAlpha(col, 0.14f)), 4 * gScale);
    dl->AddText(f, fs, ImVec2(a.x + padX, a.y + (rh - ts.y) * 0.5f), ImGui::GetColorU32(col), text);
    ImGui::Dummy(ImVec2(b.x - a.x, lh));
}

// Franja de color a la izquierda de la celda actual (marca filas nuevas o cerradas).
void rowStripe(ImU32 col) {
    ImGuiTable* t = ImGui::GetCurrentTable();
    if (!t) return;
    const ImRect r = ImGui::TableGetCellBgRect(t, t->CurrentColumn);
    ImGui::GetWindowDrawList()->AddRectFilled(r.Min, ImVec2(r.Min.x + 3 * gScale, r.Max.y), col | IM_COL32_A_MASK);
}

void tableHeaders() {
    ImGui::PushStyleColor(ImGuiCol_Text, kHeaderText);
    if (gBold) ImGui::PushFont(gBold);
    ImGui::TableHeadersRow();
    if (gBold) ImGui::PopFont();
    ImGui::PopStyleColor();
}

void sectionTitle(const char* s) {
    if (gBold) ImGui::PushFont(gBold);
    ImGui::TextUnformatted(s);
    if (gBold) ImGui::PopFont();
}

// Minigráfica de área dibujada a mano (más ligera que un ImPlot por tarjeta).
void drawSpark(ImDrawList* dl, ImVec2 a, ImVec2 b, const std::vector<float>& v, const ImVec4& col) {
    const int n = int(v.size());
    if (n < 2 || b.x <= a.x || b.y <= a.y) return;
    // Escala entre el mínimo y el máximo de la ventana: así se aprecian las variaciones
    // aunque el valor sea alto y estable (con un margen mínimo para no exagerar el ruido).
    float lo = v[0], hi = v[0];
    for (float x : v) {
        lo = std::min(lo, x);
        hi = std::max(hi, x);
    }
    const float range = std::max(hi - lo, std::max(4.0f, hi * 0.08f));
    lo = std::max(0.0f, hi - range * 1.25f);
    const float span = hi * 1.05f - lo;
    const float dx = (b.x - a.x) / float(n - 1);
    std::vector<ImVec2> pts(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i)
        pts[size_t(i)] = ImVec2(a.x + dx * i, b.y - (b.y - a.y) * (v[size_t(i)] - lo) / std::max(span, 1.0f));
    const ImDrawListFlags saved = dl->Flags;
    dl->Flags &= ~ImDrawListFlags_AntiAliasedFill;  // sin costuras entre los trapecios del relleno
    const ImU32 fill = ImGui::GetColorU32(withAlpha(col, 0.12f));
    for (int i = 0; i + 1 < n; ++i)
        dl->AddQuadFilled(pts[size_t(i)], pts[size_t(i + 1)], ImVec2(pts[size_t(i + 1)].x, b.y),
                          ImVec2(pts[size_t(i)].x, b.y), fill);
    dl->Flags = saved;
    dl->AddPolyline(pts.data(), n, ImGui::GetColorU32(withAlpha(col, 0.9f)), ImDrawFlags_None, 1.5f * gScale);
}

template <typename T>
int cmp3(const T& a, const T& b) { return a < b ? -1 : (b < a ? 1 : 0); }

int cmpStrI(const std::string& a, const std::string& b) {
    // vacíos siempre al final al ordenar ascendente
    if (a.empty() != b.empty()) return a.empty() ? 1 : -1;
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        const int x = std::tolower(static_cast<unsigned char>(a[i]));
        const int y = std::tolower(static_cast<unsigned char>(b[i]));
        if (x != y) return x < y ? -1 : 1;
    }
    return cmp3(a.size(), b.size());
}

void textRight(const char* s) {
    const float w = ImGui::CalcTextSize(s).x;
    const float avail = ImGui::GetContentRegionAvail().x;
    if (avail > w) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail - w);
    ImGui::TextUnformatted(s);
}
void textRight(const std::string& s) { textRight(s.c_str()); }
void textRightInt(long long v) { textRight(std::to_string(v)); }

void textMuted(const char* s) { ImGui::TextColored(kMuted, "%s", s); }

ImVec4 statusColor(const char* st) {
    if (!std::strcmp(st, "ESTABLISHED")) return kGreen;
    if (!std::strcmp(st, "LISTEN")) return kAccent;
    if (!std::strcmp(st, "SYN_SENT") || !std::strcmp(st, "SYN_RECV")) return kUdp;
    return kMuted;
}

// Estado TCP como punto de color + texto (los estados de cierre, atenuados).
void statusCell(const char* st) {
    if (!*st) return;
    const ImVec4 col = statusColor(st);
    const bool live = col.x != kMuted.x || col.y != kMuted.y || col.z != kMuted.z;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float r = 3.5f * gScale;
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(p.x + r, p.y + ImGui::GetTextLineHeight() * 0.5f + 0.5f), r,
                                                ImGui::GetColorU32(col));
    ImGui::SetCursorScreenPos(ImVec2(p.x + r * 2 + 7 * gScale, p.y));
    ImGui::TextColored(live ? kText : kMuted, "%s", st);
}

std::string csvField(const std::string& s) {
    if (s.find_first_of(",\"\n;") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += '"';
        out += c;
    }
    return out + "\"";
}

std::string pidText(int pid) { return pid >= 0 ? std::to_string(pid) : std::string(); }

std::string eventDetail(const ConnEvent& e) {
    if (e.open) {
        if (!e.c.hasRemote()) return "";
        if (e.interval >= 0) return "intervalo " + fmtDuration(e.interval);
        return e.burst ? "simultánea" : "primera conexión";
    }
    return std::string("duró ") + (e.baseline ? ">= " : "") + fmtDuration(e.duration);
}

// ---- VirusTotal
const ImVec4 kVtBad(0.96f, 0.30f, 0.45f, 1.0f);
const ImVec4 kVtWarn(0.96f, 0.62f, 0.25f, 1.0f);
const ImU32 kRowMalicious = IM_COL32(220, 40, 90, 52);
const ImU32 kRowSuspicious = IM_COL32(245, 150, 60, 30);

ImVec4 vtColor(const VtResult& r) {
    switch (r.severity()) {
        case 2: return kVtBad;
        case 1: return kVtWarn;
        case 0: return kGreen;
        default: return kMuted;
    }
}

// Celda "3/72" coloreada, con el desglose en el tooltip.
void vtCell(const VtResult& r, bool rightAlign = false) {
    const std::string label = r.label();
    if (label.empty()) return;
    ImGui::PushStyleColor(ImGuiCol_Text, vtColor(r));
    if (rightAlign) textRight(label);
    else ImGui::TextUnformatted(label.c_str());
    ImGui::PopStyleColor();
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort) || !ImGui::BeginTooltip()) return;
    switch (r.st) {
        case VtResult::St::Done:
            ImGui::TextColored(vtColor(r), "VirusTotal: %s", r.verdict());
            ImGui::Text("Maliciosos: %d   Sospechosos: %d", r.malicious, r.suspicious);
            ImGui::Text("Inofensivos: %d   Sin detección: %d", r.harmless, r.undetected);
            if (!r.owner.empty()) ImGui::Text("%s", r.owner.c_str());
            if (!r.country.empty()) ImGui::Text("País: %s", r.country.c_str());
            ImGui::TextDisabled("Consultado: %s", fmtClock(r.ts).c_str());
            break;
        case VtResult::St::NotFound:
            ImGui::TextUnformatted("VirusTotal nunca ha analizado este ejecutable.");
            ImGui::TextDisabled("No es necesariamente malo, pero tampoco está verificado.");
            break;
        case VtResult::St::NoAccess:
            ImGui::TextUnformatted("No se pudo leer el ejecutable para calcular su hash");
            ImGui::TextDisabled("(proceso protegido o de otro usuario: prueba con permisos de administrador).");
            break;
        case VtResult::St::Queued: ImGui::TextUnformatted("Pendiente de consultar (límite de peticiones por minuto)."); break;
        case VtResult::St::Error: ImGui::TextUnformatted("Falló la consulta; se reintentará en unos minutos."); break;
        default: break;
    }
    if (!r.path.empty()) ImGui::TextDisabled("%s", r.path.c_str());
    if (!r.sha256.empty()) ImGui::TextDisabled("SHA-256 %s", r.sha256.c_str());
    ImGui::EndTooltip();
}

// ---- Reputación (listas negras públicas + organización)
ImVec4 repColor(const RepResult& r) {
    switch (r.severity) {
        case 2: return kVtBad;
        case 1: return kVtWarn;
        case 0: return ImVec4(0.42f, 0.60f, 0.50f, 1.0f);  // verde apagado: "sin reportes" no es "seguro"
        default: return kMuted;
    }
}

void repCell(const RepResult& r) {
    const std::string label = r.label();
    if (label.empty()) return;
    ImGui::TextColored(repColor(r), "%s", label.c_str());
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort) || !ImGui::BeginTooltip()) return;
    if (!r.listsReady) {
        ImGui::TextUnformatted("Descargando las listas negras públicas...");
    } else if (r.severity > 0) {
        ImGui::TextColored(repColor(r), "Aparece en: %s", r.lists.c_str());
        if (r.severity == 2) ImGui::TextUnformatted("Listas de alta confianza: botnets, redes criminales o 3+ listas a la vez.");
        else if (r.tor && r.lists == "Tor") ImGui::TextUnformatted("Nodo de salida de la red Tor (anonimato).");
        else ImGui::TextUnformatted("Reportada por atacar o escanear otros equipos; puede ser un falso positivo.");
    } else {
        ImGui::TextUnformatted("No aparece en ninguna lista negra pública.");
        ImGui::TextDisabled("Eso no garantiza que sea segura; mira también la organización.");
    }
    if (!r.org.empty()) ImGui::Text("AS%s  %s", r.asn.c_str(), r.org.c_str());
    if (!r.country.empty()) ImGui::Text("País: %s", r.country.c_str());
    ImGui::EndTooltip();
}

// ---- persistencia de ajustes en el .ini de ImGui
void* settingsOpen(ImGuiContext*, ImGuiSettingsHandler* h, const char* name) {
    return std::strcmp(name, "Settings") == 0 ? h->UserData : nullptr;
}

void settingsReadLine(ImGuiContext*, ImGuiSettingsHandler*, void* entry, const char* line) {
    auto* s = static_cast<App::Settings*>(entry);
    float f;
    int i;
    if (std::sscanf(line, "Interval=%f", &f) == 1) s->interval = std::clamp(f, 0.25f, 10.0f);
    else if (std::sscanf(line, "Tcp=%d", &i) == 1) s->tcp = i != 0;
    else if (std::sscanf(line, "Udp=%d", &i) == 1) s->udp = i != 0;
    else if (std::sscanf(line, "OnlyEstablished=%d", &i) == 1) s->onlyEstablished = i != 0;
    else if (std::sscanf(line, "Listening=%d", &i) == 1) s->listening = i != 0;
    else if (std::sscanf(line, "Localhost=%d", &i) == 1) s->localhost = i != 0;
    else if (std::sscanf(line, "Dns=%d", &i) == 1) s->dns = i != 0;
    else if (std::sscanf(line, "HostsOnlyActive=%d", &i) == 1) s->hostsOnlyActive = i != 0;
    else if (std::sscanf(line, "GroupByDomain=%d", &i) == 1) s->groupByDomain = i != 0;
    else if (std::sscanf(line, "ProcsOnlyActive=%d", &i) == 1) s->procsOnlyActive = i != 0;
    else if (std::sscanf(line, "Span=%d", &i) == 1) s->spanIndex = std::clamp(i, 0, 3);
    else if (std::sscanf(line, "Reputation=%d", &i) == 1) s->reputation = i != 0;
    else if (std::sscanf(line, "VtEnabled=%d", &i) == 1) s->vtEnabled = i != 0;
    else if (std::sscanf(line, "VtPerMinute=%d", &i) == 1) s->vtPerMinute = std::clamp(i, 1, 10000);
    else if (std::sscanf(line, "VtPerDay=%d", &i) == 1) s->vtPerDay = std::clamp(i, 1, 10000000);
    else if (std::strncmp(line, "VtKey=", 6) == 0) std::snprintf(s->vtKey, sizeof s->vtKey, "%s", line + 6);
}

void settingsWriteAll(ImGuiContext*, ImGuiSettingsHandler* h, ImGuiTextBuffer* buf) {
    const auto* s = static_cast<const App::Settings*>(h->UserData);
    buf->appendf("[NetAnalyzer][Settings]\n");
    buf->appendf("Interval=%.2f\nTcp=%d\nUdp=%d\nOnlyEstablished=%d\nListening=%d\nLocalhost=%d\n", s->interval,
                 s->tcp, s->udp, s->onlyEstablished, s->listening, s->localhost);
    buf->appendf("Dns=%d\nHostsOnlyActive=%d\nGroupByDomain=%d\nProcsOnlyActive=%d\nSpan=%d\n", s->dns,
                 s->hostsOnlyActive, s->groupByDomain, s->procsOnlyActive, s->spanIndex);
    buf->appendf("Reputation=%d\nVtEnabled=%d\nVtPerMinute=%d\nVtPerDay=%d\nVtKey=%s\n\n", s->reputation,
                 s->vtEnabled, s->vtPerMinute, s->vtPerDay, s->vtKey);
}

enum ConnCol { CC_Proto, CC_Proc, CC_Pid, CC_Local, CC_Remote, CC_Port, CC_Service, CC_Host, CC_State, CC_Scope,
               CC_Rep, CC_VtIp, CC_VtProc, CC_Duration, CC_Since, CC_Path, CC_Count };
// El orden del enum es el orden de las columnas (TableSetColumnIndex): los intervalos, al final.
enum HostCol { HC_Ip, HC_Host, HC_Scope, HC_Rep, HC_Vt, HC_Owner, HC_Country, HC_Total, HC_Active, HC_Rate, HC_Procs,
               HC_Ports, HC_First, HC_LastSeen, HC_Avg, HC_Last, HC_Min, HC_Count };

// Organización y país: los da la reputación (Team Cymru) y, si no, VirusTotal.
const std::string& orgOf(const RepResult& rep, const VtResult& vt) { return rep.org.empty() ? vt.owner : rep.org; }
const std::string& countryOf(const RepResult& rep, const VtResult& vt) {
    return rep.country.empty() ? vt.country : rep.country;
}
enum ProcCol { PC_Name, PC_Pid, PC_Vt, PC_Tcp, PC_Udp, PC_Listen, PC_Total, PC_Hosts, PC_Last, PC_Path, PC_Count };

}  // namespace

App::App(CollectorThread& collector, Resolver& resolver, VirusTotal& vt, Reputation& rep)
    : collector_(collector), resolver_(resolver), vt_(vt), rep_(rep) {
    connSort_ = {CC_Since, false};
    hostSort_ = {HC_Total, false};
    procSort_ = {PC_Total, false};
    registerSettings();
}

void App::registerSettings() {
    ImGuiSettingsHandler h;
    h.TypeName = "NetAnalyzer";
    h.TypeHash = ImHashStr("NetAnalyzer");
    h.ReadOpenFn = settingsOpen;
    h.ReadLineFn = settingsReadLine;
    h.WriteAllFn = settingsWriteAll;
    h.UserData = &settings;
    ImGui::AddSettingsHandler(&h);
}

void App::settingsChanged() {
    ImGui::MarkIniSettingsDirty();
    dirty_ = true;
}

int App::vtColumnFlags() const { return vtActive() ? ImGuiTableColumnFlags_None : ImGuiTableColumnFlags_Disabled; }
int App::repColumnFlags() const {
    return settings.reputation ? ImGuiTableColumnFlags_None : ImGuiTableColumnFlags_Disabled;
}
int App::orgColumnFlags() const {
    return settings.reputation || vtActive() ? ImGuiTableColumnFlags_None : ImGuiTableColumnFlags_Disabled;
}

double App::viewNow() const { return collector_.paused() && lastPollTs_ > 0 ? lastPollTs_ : nowSeconds(); }

// ------------------------------------------------------------------ datos

void App::poll() {
    Snapshot snap;
    if (collector_.take(snap)) {
        lastPollMs_ = snap.ms;
        lastSockets_ = snap.conns.size();
        lastError_ = snap.error;
        if (snap.error.empty()) {
            tracker_.update(snap.conns, snap.ts);
            lastPollTs_ = snap.ts;
            rebuildSeries();
            dirty_ = true;
        }
    }
    const uint64_t gen = resolver_.generation();
    const double t = nowSeconds();
    const uint64_t vtGen = vt_.generation();
    const uint64_t repGen = rep_.generation();
    if ((gen != lastNameGen_ || vtGen != lastVtGen_ || repGen != lastRepGen_) && t - lastNameRebuild_ > 0.5) {
        lastNameGen_ = gen;  // nombres, veredictos u organizaciones nuevas
        lastVtGen_ = vtGen;
        lastRepGen_ = repGen;
        lastNameRebuild_ = t;
        dirty_ = true;
    }
}

bool App::passConn(const Conn& c) const {
    if (c.proto == Proto::TCP && !settings.tcp) return false;
    if (c.proto == Proto::UDP && !settings.udp) return false;
    const bool remote = c.hasRemote();
    if (!settings.listening && !remote) return false;
    if (!settings.localhost && remote && ipScope(c.raddr) == Scope::Loopback) return false;
    if (settings.onlyEstablished && c.proto == Proto::TCP && std::strcmp(c.status, "ESTABLISHED") != 0) return false;
    return true;
}

void App::parseFilter() {
    include_.clear();
    exclude_.clear();
    const std::string f = toLower(filter_);
    size_t i = 0;
    while (i < f.size()) {
        while (i < f.size() && f[i] == ' ') ++i;
        size_t j = i;
        while (j < f.size() && f[j] != ' ') ++j;
        if (j > i) {
            std::string term = f.substr(i, j - i);
            if (term.size() > 1 && term[0] == '-') exclude_.push_back(term.substr(1));
            else include_.push_back(term);
        }
        i = j;
    }
    dirty_ = true;
}

bool App::matchFilter(const std::string& hay) const {
    for (const auto& t : include_)
        if (hay.find(t) == std::string::npos) return false;
    for (const auto& t : exclude_)
        if (hay.find(t) != std::string::npos) return false;
    return true;
}

void App::setFilter(const std::string& text) {
    std::snprintf(filter_, sizeof filter_, "%s", text.c_str());
    parseFilter();
}

void App::rebuildViews() {
    const bool filtering = !include_.empty() || !exclude_.empty();

    connRows_.clear();
    for (auto& [k, lc] : tracker_.live) {
        const Conn& c = lc.c;
        if (!passConn(c)) continue;
        ConnRow r{&lc, c.hasRemote() ? resolver_.name(c.raddr) : std::string(), {}, {}, {}, {}, exePath(c.pid, c.pname)};
        if (c.hasRemote()) {
            r.vtIp = vt_.ip(c.raddr, c.rstr);
            r.rep = rep_.lookup(c.raddr);
        }
        r.vtProc = vt_.process(c.pid, c.pname);
        if (filtering) {
            r.hay = toLower(std::string(protoName(c.proto)) + " " + c.pname + " " + pidText(c.pid) + " " + c.lstr +
                            ":" + std::to_string(c.lport) + " " + c.rstr + ":" + std::to_string(c.rport) + " " +
                            connService(c) + " " + r.host + " " + c.status + " " + scopeName(ipScope(c.raddr)) + " " +
                            orgOf(r.rep, r.vtIp) + " " + r.rep.label() + " " + r.rep.lists + " " +
                            r.vtIp.verdict() + " " + r.vtProc.verdict() + " " + r.path);
            if (!matchFilter(r.hay)) continue;
        }
        connRows_.push_back(std::move(r));
    }
    connSort_.dirty = true;

    // Alertas (reputación + VirusTotal): todos los hosts y procesos vistos, no solo los filtrados.
    vtAlerts_ = vtMalicious_ = 0;
    auto countAlert = [this](int severity) {
        if (severity >= 1) ++vtAlerts_;
        if (severity == 2) ++vtMalicious_;
    };

    hostRows_.clear();
    for (auto& [ip, h] : tracker_.hosts) {
        const VtResult vt = vt_.ip(ip, h.ipStr);
        const RepResult rep = rep_.lookup(ip);
        countAlert(std::max(vt.severity(), rep.severity));
        if (!settings.localhost && h.scope == Scope::Loopback) continue;
        if (settings.hostsOnlyActive && h.active == 0) continue;
        HostRow r{&h, resolver_.name(ip), {}, vt, rep};
        if (filtering) {
            r.hay = toLower(h.ipStr + " " + r.name + " " + scopeName(h.scope) + " " + h.procsStr + " " + h.portsStr +
                            " " + orgOf(rep, vt) + " " + countryOf(rep, vt) + " AS" + rep.asn + " " + rep.label() +
                            " " + rep.lists + " " + vt.verdict());
            if (!matchFilter(r.hay)) continue;
        }
        hostRows_.push_back(std::move(r));
    }
    hostSort_.dirty = true;

    // Top de hosts para la gráfica de barras (por IP o agrupado por dominio).
    barLabels_.clear();
    barValues_.clear();
    barHosts_.clear();
    std::vector<std::pair<double, std::string>> top;
    std::vector<IpAddr> topIps;
    if (settings.groupByDomain) {
        std::map<std::string, double> byDomain;
        for (const auto& r : hostRows_) byDomain[r.name.empty() ? r.h->ipStr : baseDomain(r.name)] += r.h->total;
        for (auto& [d, v] : byDomain) top.push_back({v, d});
        std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    } else {
        std::vector<const HostRow*> sorted;
        for (const auto& r : hostRows_) sorted.push_back(&r);
        std::sort(sorted.begin(), sorted.end(), [](const HostRow* a, const HostRow* b) {
            return a->h->total != b->h->total ? a->h->total > b->h->total : a->h->ip < b->h->ip;
        });
        for (const HostRow* r : sorted) {
            top.push_back({double(r->h->total), r->name.empty() ? r->h->ipStr : r->name});
            topIps.push_back(r->h->ip);
        }
    }
    const size_t n = std::min<size_t>(top.size(), 15);
    for (size_t i = n; i-- > 0;) {  // al revés: ImPlot dibuja la barra 0 abajo
        std::string label = top[i].second;
        if (label.size() > 34) label = "..." + label.substr(label.size() - 31);
        barLabels_.push_back(label);
        barValues_.push_back(top[i].first);
        if (!settings.groupByDomain) barHosts_.push_back(topIps[i]);
    }

    procRows_.clear();
    for (auto& [pid, p] : tracker_.procs) {
        const VtResult vt = vt_.process(p.pid, p.name);
        countAlert(vt.severity());
        if (settings.procsOnlyActive && p.activeTcp + p.activeUdp == 0) continue;
        ProcRow r{&p, {}, vt, exePath(p.pid, p.name)};
        if (filtering) {
            r.hay = toLower(p.name + " " + pidText(p.pid) + " " + r.path + " " + vt.verdict());
            if (!matchFilter(r.hay)) continue;
        }
        procRows_.push_back(std::move(r));
    }
    procSort_.dirty = true;

    eventRows_.clear();
    for (auto it = tracker_.events.rbegin(); it != tracker_.events.rend() && eventRows_.size() < 3000; ++it) {
        const ConnEvent& e = *it;
        if (!passConn(e.c)) continue;
        EventRow r{&e, e.c.hasRemote() ? resolver_.name(e.c.raddr) : std::string()};
        if (filtering) {
            const std::string hay = toLower(std::string(protoName(e.c.proto)) + " " + e.c.pname + " " +
                                            pidText(e.c.pid) + " " + e.c.rstr + ":" + std::to_string(e.c.rport) +
                                            " " + r.host + " " + connService(e.c));
            if (!matchFilter(hay)) continue;
        }
        eventRows_.push_back(std::move(r));
    }

    hasDetail_ = false;
    if (hasSelHost_ && tracker_.hosts.count(selHost_)) {
        detailHost_ = selHost_;
        hasDetail_ = true;
    } else {
        const HostStats* best = nullptr;
        for (const auto& r : hostRows_)
            if (!best || r.h->total > best->total || (r.h->total == best->total && r.h->ip < best->ip)) best = r.h;
        if (best) {
            detailHost_ = best->ip;
            hasDetail_ = true;
        }
    }
    hostEventRows_.clear();
    if (hasDetail_) {
        const HostStats& h = tracker_.hosts.at(detailHost_);
        const std::string host = resolver_.name(detailHost_);
        for (auto e = h.events.rbegin(); e != h.events.rend(); ++e) hostEventRows_.push_back({&*e, host});
    }
}

void App::rebuildSeries() {
    tsSeries_.clear();
    rateTcp_.clear();
    rateUdp_.clear();
    actTcp_.clear();
    actUdp_.clear();
    for (const Sample& s : tracker_.timeline) {
        tsSeries_.push_back(s.ts);
        rateTcp_.push_back(s.rateTcp);
        rateUdp_.push_back(s.rateUdp);
        actTcp_.push_back(s.activeTcp);
        actUdp_.push_back(s.activeUdp);
    }
    sparkTcp_.clear();
    sparkUdp_.clear();
    sparkNew_.clear();
    const size_t from = tracker_.timeline.size() > 60 ? tracker_.timeline.size() - 60 : 0;
    for (size_t i = from; i < tracker_.timeline.size(); ++i) {
        const Sample& s = tracker_.timeline[i];
        sparkTcp_.push_back(float(s.activeTcp));
        sparkUdp_.push_back(float(s.activeUdp));
        sparkNew_.push_back(float(s.rateTcp + s.rateUdp));
    }
}

// ------------------------------------------------------------------ ordenación

void App::sortConns() {
    const double now = viewNow();
    const int col = connSort_.col;
    const bool asc = connSort_.asc;
    std::stable_sort(connRows_.begin(), connRows_.end(), [&](const ConnRow& ra, const ConnRow& rb) {
        const Conn& a = ra.lc->c;
        const Conn& b = rb.lc->c;
        int r = 0;
        switch (col) {
            case CC_Proto: r = cmp3(a.proto, b.proto); break;
            case CC_Proc: r = cmpStrI(a.pname, b.pname); break;
            case CC_Pid: r = cmp3(a.pid, b.pid); break;
            case CC_Local: r = a.laddr == b.laddr ? cmp3(a.lport, b.lport) : cmp3(a.laddr, b.laddr); break;
            case CC_Remote: r = a.raddr == b.raddr ? cmp3(a.rport, b.rport) : cmp3(a.raddr, b.raddr); break;
            case CC_Port: r = cmp3(a.rport, b.rport); break;
            case CC_Service: r = cmpStrI(connService(a), connService(b)); break;
            case CC_Host: r = cmpStrI(ra.host, rb.host); break;
            case CC_State: r = std::strcmp(a.status, b.status); break;
            case CC_Scope: r = cmp3(int(ipScope(a.raddr)), int(ipScope(b.raddr))); break;
            case CC_Rep: r = cmp3(ra.rep.sortKey(), rb.rep.sortKey()); break;
            case CC_VtIp: r = cmp3(ra.vtIp.sortKey(), rb.vtIp.sortKey()); break;
            case CC_VtProc: r = cmp3(ra.vtProc.sortKey(), rb.vtProc.sortKey()); break;
            case CC_Duration: r = cmp3(ra.lc->age(now), rb.lc->age(now)); break;
            case CC_Since: r = cmp3(ra.lc->firstSeen, rb.lc->firstSeen); break;
            case CC_Path: r = cmpStrI(ra.path, rb.path); break;
        }
        if (r == 0) r = cmp3(a.lport, b.lport);  // desempate estable entre muestreos
        if (r == 0) r = cmp3(a.raddr, b.raddr);
        return asc ? r < 0 : r > 0;
    });
}

void App::sortHosts() {
    const double now = viewNow();
    const int col = hostSort_.col;
    const bool asc = hostSort_.asc;
    std::stable_sort(hostRows_.begin(), hostRows_.end(), [&](const HostRow& ra, const HostRow& rb) {
        const HostStats& a = *ra.h;
        const HostStats& b = *rb.h;
        int r = 0;
        switch (col) {
            case HC_Ip: r = cmp3(a.ip, b.ip); break;
            case HC_Host: r = cmpStrI(ra.name, rb.name); break;
            case HC_Scope: r = cmp3(int(a.scope), int(b.scope)); break;
            case HC_Rep: r = cmp3(ra.rep.sortKey(), rb.rep.sortKey()); break;
            case HC_Vt: r = cmp3(ra.vt.sortKey(), rb.vt.sortKey()); break;
            case HC_Owner: r = cmpStrI(orgOf(ra.rep, ra.vt), orgOf(rb.rep, rb.vt)); break;
            case HC_Country: r = cmpStrI(countryOf(ra.rep, ra.vt), countryOf(rb.rep, rb.vt)); break;
            case HC_Total: r = cmp3(a.total, b.total); break;
            case HC_Active: r = cmp3(a.active, b.active); break;
            case HC_Rate: r = cmp3(a.ratePerMin(now), b.ratePerMin(now)); break;
            case HC_Avg: r = cmp3(a.avgInterval(), b.avgInterval()); break;
            case HC_Last: r = cmp3(a.lastInterval(), b.lastInterval()); break;
            case HC_Min: r = cmp3(a.minInterval, b.minInterval); break;
            case HC_Procs: r = cmpStrI(a.procsStr, b.procsStr); break;
            case HC_Ports: r = cmpStrI(a.portsStr, b.portsStr); break;
            case HC_First: r = cmp3(a.firstSeen, b.firstSeen); break;
            case HC_LastSeen: r = cmp3(a.lastSeen, b.lastSeen); break;
        }
        if (r == 0) r = cmp3(a.ip, b.ip);
        return asc ? r < 0 : r > 0;
    });
}

void App::sortProcs() {
    const int col = procSort_.col;
    const bool asc = procSort_.asc;
    std::stable_sort(procRows_.begin(), procRows_.end(), [&](const ProcRow& ra, const ProcRow& rb) {
        const ProcStats& a = *ra.p;
        const ProcStats& b = *rb.p;
        int r = 0;
        switch (col) {
            case PC_Name: r = cmpStrI(a.name, b.name); break;
            case PC_Pid: r = cmp3(a.pid, b.pid); break;
            case PC_Vt: r = cmp3(ra.vt.sortKey(), rb.vt.sortKey()); break;
            case PC_Path: r = cmpStrI(ra.path, rb.path); break;
            case PC_Tcp: r = cmp3(a.activeTcp, b.activeTcp); break;
            case PC_Udp: r = cmp3(a.activeUdp, b.activeUdp); break;
            case PC_Listen: r = cmp3(a.listening, b.listening); break;
            case PC_Total: r = cmp3(a.total, b.total); break;
            case PC_Hosts: r = cmp3(a.hosts.size(), b.hosts.size()); break;
            case PC_Last: r = cmp3(a.lastSeen, b.lastSeen); break;
        }
        if (r == 0) r = cmp3(a.pid, b.pid);
        return asc ? r < 0 : r > 0;
    });
}

// Lee la especificación de orden de la tabla actual; true si hay que reordenar.
static bool takeSort(int& col, bool& asc, bool& dirty) {
    if (ImGuiTableSortSpecs* sp = ImGui::TableGetSortSpecs()) {
        if (sp->SpecsDirty) {
            if (sp->SpecsCount > 0) {
                col = int(sp->Specs[0].ColumnUserID);
                asc = sp->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
            }
            sp->SpecsDirty = false;
            dirty = true;
        }
    }
    const bool r = dirty;
    dirty = false;
    return r;
}

// ------------------------------------------------------------------ dibujo

void App::frame() {
    if (firstFrame_) {  // los ajustes se cargan del .ini en el primer NewFrame()
        firstFrame_ = false;
        collector_.setInterval(settings.interval);
        resolver_.enabled = settings.dns;
        rep_.setEnabled(settings.reputation);
        applyVtSettings();
        dirty_ = true;
    }
    poll();
    if (dirty_) {
        rebuildViews();
        dirty_ = false;
    }
    gScale = scale;
    gBold = fonts.bold;
    gSmall = fonts.label;
    gIcons = fonts.icons;

    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) focusFilter_ = true;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_P, false)) collector_.setPaused(!collector_.paused());
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S, false)) exportCsv();
    if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) collector_.refreshNow();

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    const ImGuiWindowFlags wflags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                    ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::Begin("##main", nullptr, wflags);

    drawToolbar();
    ImGui::Dummy(ImVec2(0, 2 * scale));
    drawCards();

    // La barra de estado ocupa una franja fija abajo; el contenido llega justo hasta ella.
    const float statusH = ImGui::GetTextLineHeight() + 12 * scale;
    const ImGuiStyle& st = ImGui::GetStyle();
    ImGui::BeginChild("##content", ImVec2(0, -(statusH + st.ItemSpacing.y - st.WindowPadding.y)), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14 * scale, 8 * scale));
    const bool tabs = ImGui::BeginTabBar("##tabs");
    ImGui::PopStyleVar();
    if (tabs) {
        char label[64];
        std::snprintf(label, sizeof label, "Conexiones  \xC2\xB7  %zu###conns", connRows_.size());
        if (beginTab(label, 0)) {
            drawConnections();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "Hosts / IPs  \xC2\xB7  %zu###hosts", hostRows_.size());
        if (beginTab(label, 1)) {
            drawHosts();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "Procesos  \xC2\xB7  %zu###procs", procRows_.size());
        if (beginTab(label, 2)) {
            drawProcesses();
            ImGui::EndTabItem();
        }
        if (beginTab("Actividad###activity", 3)) {
            drawActivity();
            ImGui::EndTabItem();
        }
        pendingTab_ = -1;
        ImGui::EndTabBar();
    }
    ImGui::EndChild();

    drawStatusBar();
    drawModals();
    ImGui::End();
}

// Pestaña con el texto atenuado si no está seleccionada y un subrayado de acento si lo está.
bool App::beginTab(const char* label, int index) {
    const bool wasCurrent = currentTab_ == index;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14 * scale, 8 * scale));
    ImGui::PushStyleColor(ImGuiCol_Text, wasCurrent ? kText : kMuted);
    if (gBold) ImGui::PushFont(gBold);
    const bool open =
        ImGui::BeginTabItem(label, nullptr, pendingTab_ == index ? ImGuiTabItemFlags_SetSelected : 0);
    if (gBold) ImGui::PopFont();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    if (!open) return false;
    currentTab_ = index;
    const ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(a.x + 6 * scale, b.y - 2 * scale), ImVec2(b.x - 6 * scale, b.y),
                                              ImGui::GetColorU32(kAccent), 1 * scale);
    return true;
}

void App::drawToolbar() {
    const ImGuiStyle& st = ImGui::GetStyle();
    const float sp = st.ItemSpacing.x;
    const float h = ImGui::GetFrameHeight();
    const bool paused = collector_.paused();
    const std::string pauseLbl = withIcon(paused ? ICON_PLAY : ICON_PAUSE, paused ? "Reanudar" : "Pausar") + "###pause";
    if (paused) {
        ImGui::PushStyleColor(ImGuiCol_Button, withAlpha(kAccent, 0.85f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccent);
        ImGui::PushStyleColor(ImGuiCol_Border, kAccent);
    }
    if (ImGui::Button(pauseLbl.c_str(), ImVec2(112 * scale, 0))) collector_.setPaused(!paused);
    if (paused) ImGui::PopStyleColor(3);
    ImGui::SetItemTooltip(paused ? "Reanudar la captura (Ctrl+P)" : "Congelar la vista (Ctrl+P)");
    ImGui::SameLine();
    if (ImGui::Button(withIcon(ICON_REFRESH, "Actualizar").c_str())) collector_.refreshNow();
    ImGui::SetItemTooltip("Muestrear ahora (F5)");
    ImGui::SameLine();
    static const float kIntervals[] = {0.25f, 0.5f, 1.0f, 2.0f, 5.0f, 10.0f};
    char preview[32];
    std::snprintf(preview, sizeof preview, "Muestreo  %g s", settings.interval);
    ImGui::SetNextItemWidth(140 * scale);
    ImGui::PushStyleColor(ImGuiCol_Button, st.Colors[ImGuiCol_FrameBg]);  // flecha del combo sin bloque propio
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, st.Colors[ImGuiCol_FrameBgHovered]);
    const bool comboOpen = ImGui::BeginCombo("##interval", preview);
    ImGui::PopStyleColor(2);
    if (comboOpen) {
        for (float v : kIntervals) {
            char item[16];
            std::snprintf(item, sizeof item, "%g s", v);
            if (ImGui::Selectable(item, v == settings.interval)) {
                settings.interval = v;
                collector_.setInterval(v);
                ImGui::MarkIniSettingsDirty();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SetItemTooltip("Cada cuánto se consulta al sistema. Conexiones más cortas que esto pueden no verse.");
    ImGui::SameLine();

    // Acciones a la derecha; el filtro ocupa el hueco intermedio.
    const bool vtOn = vtActive();
    const std::string vtLbl = withIcon(ICON_SHIELD, vtOn ? "VirusTotal activo" : "VirusTotal") + "###vt";
    const std::string resetLbl = withIcon(ICON_RESET, "Reiniciar");
    const std::string exportLbl = withIcon(ICON_EXPORT, "Exportar CSV");
    auto btnW = [&](const std::string& s) { return ImGui::CalcTextSize(s.c_str(), nullptr, true).x + st.FramePadding.x * 2; };
    const float rightW = btnW(vtLbl) + btnW(resetLbl) + btnW(exportLbl) + sp * 2;
    const float filterW = std::max(220 * scale, ImGui::GetContentRegionAvail().x - rightW - h - sp * 2 - 16 * scale);

    if (focusFilter_) {
        ImGui::SetKeyboardFocusHere();
        focusFilter_ = false;
    }
    const ImVec2 fpos = ImGui::GetCursorScreenPos();
    const float iconPad = gIcons ? ImGui::GetFontSize() + 4 * scale : 0;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(st.FramePadding.x + iconPad, st.FramePadding.y));
    if (filter_[0]) ImGui::PushStyleColor(ImGuiCol_Border, withAlpha(kAccent, 0.6f));
    ImGui::SetNextItemWidth(filterW);
    if (ImGui::InputTextWithHint("##filter", "Filtrar por IP, dominio, proceso, puerto, estado...   (-texto excluye)",
                                 filter_, sizeof filter_))
        parseFilter();
    if (filter_[0]) ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    ImGui::SetItemTooltip("Ctrl+F. Varias palabras se combinan; \"-texto\" excluye.");
    if (gIcons)
        ImGui::GetWindowDrawList()->AddText(ImVec2(fpos.x + st.FramePadding.x, fpos.y + st.FramePadding.y),
                                            ImGui::GetColorU32(filter_[0] ? kAccent : kMuted), ICON_SEARCH);
    ImGui::SameLine(0, 4 * scale);
    ImGui::BeginDisabled(!filter_[0]);
    if (ImGui::Button("##clear", ImVec2(h, h))) setFilter("");
    {
        // Aspa dibujada a mano: el glifo del icono no queda centrado en el botón.
        const ImVec2 c((ImGui::GetItemRectMin().x + ImGui::GetItemRectMax().x) * 0.5f,
                       (ImGui::GetItemRectMin().y + ImGui::GetItemRectMax().y) * 0.5f);
        const float r = 4.5f * scale;
        const ImU32 col = ImGui::GetColorU32(ImGuiCol_Text);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddLine(ImVec2(c.x - r, c.y - r), ImVec2(c.x + r, c.y + r), col, 1.4f * scale);
        dl->AddLine(ImVec2(c.x - r, c.y + r), ImVec2(c.x + r, c.y - r), col, 1.4f * scale);
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Limpiar filtro");

    ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - rightW);
    if (vtOn) {
        const ImVec4 c = vtMalicious_ ? kVtBad : kGreen;
        ImGui::PushStyleColor(ImGuiCol_Button, withAlpha(c, 0.16f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, withAlpha(c, 0.26f));
        ImGui::PushStyleColor(ImGuiCol_Border, withAlpha(c, 0.55f));
    }
    if (ImGui::Button(vtLbl.c_str())) vtSettingsRequested_ = true;
    if (vtOn) ImGui::PopStyleColor(3);
    ImGui::SetItemTooltip("Comprobar IPs y ejecutables en VirusTotal (como Process Explorer)");
    ImGui::SameLine();
    if (ImGui::Button(resetLbl.c_str())) {
        tracker_.reset();
        hasSelHost_ = hasSelConn_ = false;
        rebuildSeries();
        // Inmediato, no diferido: las tablas de este mismo frame apuntaban a datos ya borrados.
        rebuildViews();
        toast("Estadísticas reiniciadas");
    }
    ImGui::SetItemTooltip("Borra las estadísticas acumuladas");
    ImGui::SameLine();
    if (ImGui::Button(exportLbl.c_str())) exportCsv();
    ImGui::SetItemTooltip("Exporta la pestaña actual con el filtro aplicado (Ctrl+S)");

    // Segunda fila: interruptores de lo que se muestra y del análisis.
    bool changed = false;
    ImGui::AlignTextToFramePadding();
    textMuted("Mostrar");
    ImGui::SameLine();
    changed |= chip("TCP", &settings.tcp, kTcp);
    ImGui::SameLine();
    changed |= chip("UDP", &settings.udp, kUdp);
    ImGui::SameLine();
    changed |= chip("Solo ESTABLISHED", &settings.onlyEstablished, kGreen);
    ImGui::SameLine();
    changed |= chip("Escuchas / UDP sin destino", &settings.listening, kAccent);
    ImGui::SetItemTooltip("Muestra sockets LISTEN y UDP que no tienen IP remota fija (DNS, mDNS, QUIC...)");
    ImGui::SameLine();
    changed |= chip("Localhost", &settings.localhost, kAccent);
    ImGui::SameLine();
    vSeparator();
    ImGui::SameLine();
    textMuted("Análisis");
    ImGui::SameLine();
    if (chip("Resolver nombres", &settings.dns, kAccent)) {
        resolver_.enabled = settings.dns;
        changed = true;
    }
    ImGui::SetItemTooltip("Resuelve el nombre (DNS inverso) de cada IP remota");
    ImGui::SameLine();
    if (chip("Reputación", &settings.reputation, kGreen)) {
        rep_.setEnabled(settings.reputation);
        changed = true;
    }
    ImGui::SetItemTooltip("Marca las IPs que aparecen en listas negras públicas (abuse.ch, Spamhaus, IPsum,\n"
                          "Emerging Threats, CINS, blocklist.de, Tor) y muestra la organización de cada IP.\n"
                          "Sin API key ni límites: las listas se descargan y se consultan en tu equipo.");
    if (changed) settingsChanged();
}

void App::drawCards() {
    int hostsActive = 0, procsActive = 0, tcp = 0, udp = 0;
    for (const auto& [ip, h] : tracker_.hosts)
        if (h.active > 0) ++hostsActive;
    for (const auto& [pid, p] : tracker_.procs) {
        if (p.activeTcp + p.activeUdp > 0) ++procsActive;
        tcp += p.activeTcp;
        udp += p.activeUdp;
    }
    const double rate = tracker_.timeline.empty() ? 0
                                                  : tracker_.timeline.back().rateTcp + tracker_.timeline.back().rateUdp;
    char hosts[32], rateStr[32];
    std::snprintf(hosts, sizeof hosts, "%d / %zu", hostsActive, tracker_.hosts.size());
    std::snprintf(rateStr, sizeof rateStr, "%.1f", rate);
    const bool alertsOn = settings.reputation || vtActive();
    const std::string vtValue = std::to_string(vtAlerts_);
    const ImVec4 vtCol = vtMalicious_ ? kVtBad : (vtAlerts_ ? kVtWarn : kGreen);

    struct Card { const char* title; std::string value; ImVec4 color; const std::vector<float>* spark; const char* tip; };
    const Card cards[] = {
        {"TCP ACTIVAS", std::to_string(tcp), kTcp, &sparkTcp_, "Sockets TCP abiertos ahora (incluye LISTEN)"},
        {"UDP ACTIVOS", std::to_string(udp), kUdp, &sparkUdp_, "Sockets UDP abiertos ahora"},
        {"HOSTS ACTIVOS / VISTOS", hosts, kViolet, nullptr, "IPs remotas distintas: con conexión ahora / en total"},
        {"PROCESOS CON RED", std::to_string(procsActive), kAccent, nullptr, "Procesos con algún socket abierto"},
        {"NUEVAS CONEXIONES / S", rateStr, kGreen, &sparkNew_, "Aperturas detectadas en el último muestreo"},
        {"CONEXIONES VISTAS", std::to_string(tracker_.totalOpens), kMuted, nullptr, "Total desde el inicio"},
        {"ALERTAS", vtValue, vtCol, nullptr,
         "IPs en listas negras públicas y, si VirusTotal está activo, IPs o ejecutables detectados.\n"
         "Filtra por \"malicioso\" o \"sospechoso\" para verlos."},
    };
    const int n = int(sizeof cards / sizeof cards[0]) - (alertsOn ? 0 : 1);  // la última es la de alertas
    const ImGuiStyle& st = ImGui::GetStyle();
    const float sp = st.ItemSpacing.x;
    const float w = (ImGui::GetContentRegionAvail().x - sp * (n - 1)) / n;
    ImFont* labelFont = gSmall ? gSmall : ImGui::GetFont();
    ImFont* big = fonts.big ? fonts.big : ImGui::GetFont();
    const float smallPx = fontPx(labelFont), bigPx = fontPx(big);
    const float pad = 14 * scale;
    const float h = pad * 2 + smallPx + 6 * scale + bigPx;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    for (int i = 0; i < n; ++i) {
        const Card& c = cards[i];
        const bool isAlerts = i == int(sizeof cards / sizeof cards[0]) - 1;
        ImGui::PushID(i);
        const ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::InvisibleButton("##card", ImVec2(w, h));
        const bool hov = ImGui::IsItemHovered();
        if (c.tip) ImGui::SetItemTooltip("%s", c.tip);
        const ImVec2 q(p.x + w, p.y + h);
        dl->AddRectFilled(p, q, ImGui::GetColorU32(ImGuiCol_ChildBg), st.ChildRounding);
        dl->AddRect(p, q, ImGui::GetColorU32(hov ? ImVec4(1, 1, 1, 0.12f) : st.Colors[ImGuiCol_Border]),
                    st.ChildRounding);
        if (c.spark)
            drawSpark(dl, ImVec2(p.x + w * 0.50f, p.y + pad + smallPx + 2 * scale), ImVec2(q.x - pad * 0.75f, q.y - pad * 0.7f),
                      *c.spark, c.color);
        dl->AddCircleFilled(ImVec2(p.x + pad + 3 * scale, p.y + pad + smallPx * 0.5f + 0.5f), 3.5f * scale,
                            ImGui::GetColorU32(c.color));
        dl->PushClipRect(p, ImVec2(q.x - pad * 0.5f, q.y), true);
        dl->AddText(labelFont, smallPx, ImVec2(p.x + pad + 13 * scale, p.y + pad), ImGui::GetColorU32(kMuted), c.title);
        dl->AddText(big, bigPx, ImVec2(p.x + pad, p.y + pad + smallPx + 6 * scale),
                    ImGui::GetColorU32(isAlerts ? c.color : kText), c.value.c_str());
        dl->PopClipRect();
        ImGui::PopID();
        if (i + 1 < n) ImGui::SameLine();
    }
}

void App::ipIntelMenu(const std::string& ip) {
    if (ImGui::MenuItem("Ver IP en AbuseIPDB")) openInBrowser("https://www.abuseipdb.com/check/" + ip);
    if (ImGui::MenuItem("Ver IP en VirusTotal")) openInBrowser("https://www.virustotal.com/gui/ip-address/" + ip);
    if (settings.vtEnabled && ImGui::MenuItem("Volver a comprobar IP en VirusTotal")) vt_.recheckIp(ip);
}

const std::string& App::exePath(int pid, const std::string& name) {
    auto it = pathCache_.find(pid);
    if (it == pathCache_.end() || it->second.first != name)
        it = pathCache_.insert_or_assign(pid, std::make_pair(name, processPath(pid))).first;
    return it->second.second;
}

void App::vtProcMenu(int pid, const std::string& name, const VtResult& vt, const std::string& path) {
    if (!vt.sha256.empty() && ImGui::MenuItem("Ver ejecutable en VirusTotal"))
        openInBrowser("https://www.virustotal.com/gui/file/" + vt.sha256);
    if (settings.vtEnabled && pid > 4 && ImGui::MenuItem("Volver a comprobar ejecutable en VirusTotal"))
        vt_.recheckProcess(pid, name);
    if (!path.empty() && ImGui::MenuItem("Copiar ruta del ejecutable")) ImGui::SetClipboardText(path.c_str());
}

void App::connMenu(const Conn& c, const std::string& host, const VtResult& vtProc, const std::string& path) {
    if (c.hasRemote()) {
        if (ImGui::MenuItem("Copiar IP remota")) ImGui::SetClipboardText(c.rstr.c_str());
        if (ImGui::MenuItem("Copiar IP:puerto"))
            ImGui::SetClipboardText(fmtAddr(c.rstr, c.rport, c.raddr.family == 6).c_str());
        if (!host.empty() && ImGui::MenuItem("Copiar host / dominio")) ImGui::SetClipboardText(host.c_str());
        if (ImGui::MenuItem("Filtrar por esta IP")) setFilter(c.rstr);
        if (ImGui::MenuItem("Ver en la pestaña Hosts")) {
            selHost_ = c.raddr;
            hasSelHost_ = true;
            pendingTab_ = 1;
            dirty_ = true;
        }
        if (ImGui::MenuItem("Buscar IP en ipinfo.io")) openInBrowser("https://ipinfo.io/" + c.rstr);
        if (ipScope(c.raddr) == Scope::Public) ipIntelMenu(c.rstr);
        ImGui::Separator();
    }
    if (!c.pname.empty() && ImGui::MenuItem("Filtrar por este proceso")) setFilter(c.pname);
    vtProcMenu(c.pid, c.pname, vtProc, path);
    if (c.pid > 4 && ImGui::MenuItem("Terminar proceso...")) requestKill(c.pid, c.pname);
}

void App::drawConnections() {
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                  ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("conns", CC_Count, flags)) return;
    const float s = scale;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_NoHide, 52 * s, CC_Proto);
    ImGui::TableSetupColumn("Proceso", 0, 160 * s, CC_Proc);
    ImGui::TableSetupColumn("PID", 0, 60 * s, CC_Pid);
    ImGui::TableSetupColumn("Local", 0, 170 * s, CC_Local);
    ImGui::TableSetupColumn("IP remota", 0, 140 * s, CC_Remote);
    ImGui::TableSetupColumn("Puerto", 0, 50 * s, CC_Port);
    ImGui::TableSetupColumn("Servicio", 0, 75 * s, CC_Service);
    ImGui::TableSetupColumn("Host / Dominio", 0, 230 * s, CC_Host);
    ImGui::TableSetupColumn("Estado", 0, 100 * s, CC_State);
    ImGui::TableSetupColumn("Ámbito", 0, 65 * s, CC_Scope);
    ImGui::TableSetupColumn("Reputación", ImGuiTableColumnFlags_PreferSortDescending | repColumnFlags(), 90 * s, CC_Rep);
    ImGui::TableSetupColumn("VT IP", ImGuiTableColumnFlags_PreferSortDescending | vtColumnFlags(), 70 * s, CC_VtIp);
    ImGui::TableSetupColumn("VT proceso", ImGuiTableColumnFlags_PreferSortDescending | vtColumnFlags(), 85 * s,
                            CC_VtProc);
    ImGui::TableSetupColumn("Duración", 0, 80 * s, CC_Duration);
    ImGui::TableSetupColumn("Desde", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending,
                            70 * s, CC_Since);
    ImGui::TableSetupColumn("Ruta del ejecutable", 0, 420 * s, CC_Path);
    tableHeaders();
    if (takeSort(connSort_.col, connSort_.asc, connSort_.dirty)) sortConns();

    const double now = viewNow();
    ImGuiListClipper clipper;
    clipper.Begin(int(connRows_.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ConnRow& r = connRows_[size_t(i)];
            const LiveConn& lc = *r.lc;
            const Conn& c = lc.c;
            ImGui::TableNextRow();
            const int sev = std::max({r.vtIp.severity(), r.vtProc.severity(), r.rep.severity});
            if (lc.st == LiveConn::St::New) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowNew);
            else if (lc.st == LiveConn::St::Closed) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowClosed);
            else if (sev == 2) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowMalicious);
            else if (sev == 1) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowSuspicious);
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(CC_Proto);
            if (lc.st == LiveConn::St::New) rowStripe(kRowNew);
            else if (lc.st == LiveConn::St::Closed) rowStripe(kRowClosed);
            else if (sev == 2) rowStripe(kRowMalicious);
            const ConnKey key = keyOf(c);
            if (ImGui::Selectable("##row", hasSelConn_ && selConn_ == key,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                selConn_ = key;
                hasSelConn_ = true;
            }
            if (ImGui::BeginPopupContextItem("##ctx")) {
                connMenu(c, r.host, r.vtProc, r.path);
                ImGui::EndPopup();
            }
            ImGui::SameLine(0, 0);
            pill(protoName(c.proto), protoColor(c.proto));
            if (ImGui::TableSetColumnIndex(CC_Proc)) {
                ImGui::TextUnformatted(c.pname.empty() ? "?" : c.pname.c_str());
                if (!r.path.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal))
                    ImGui::SetTooltip("%s", r.path.c_str());
            }
            if (ImGui::TableSetColumnIndex(CC_Pid)) textRight(pidText(c.pid));
            if (ImGui::TableSetColumnIndex(CC_Local))
                ImGui::TextUnformatted(fmtAddr(c.lstr, c.lport, c.laddr.family == 6).c_str());
            if (ImGui::TableSetColumnIndex(CC_Remote)) {
                if (c.hasRemote()) ImGui::TextUnformatted(c.rstr.c_str());
                else textMuted("*");
            }
            if (ImGui::TableSetColumnIndex(CC_Port) && c.rport) textRightInt(c.rport);
            if (ImGui::TableSetColumnIndex(CC_Service)) ImGui::TextUnformatted(connService(c));
            if (ImGui::TableSetColumnIndex(CC_Host)) {
                const std::string& org = orgOf(r.rep, r.vtIp);
                if (!r.host.empty()) ImGui::TextColored(kLink, "%s", r.host.c_str());
                else if (!org.empty()) ImGui::TextColored(kMuted, "(%s)", org.c_str());  // organización propietaria
            }
            if (ImGui::TableSetColumnIndex(CC_State)) statusCell(c.status);
            if (ImGui::TableSetColumnIndex(CC_Scope) && c.hasRemote()) textMuted(scopeName(ipScope(c.raddr)));
            if (ImGui::TableSetColumnIndex(CC_Rep)) repCell(r.rep);
            if (ImGui::TableSetColumnIndex(CC_VtIp)) vtCell(r.vtIp, true);
            if (ImGui::TableSetColumnIndex(CC_VtProc)) vtCell(r.vtProc, true);
            if (ImGui::TableSetColumnIndex(CC_Duration))
                textRight((lc.baseline ? ">= " : "") + fmtDuration(lc.age(now)));
            if (ImGui::TableSetColumnIndex(CC_Since)) ImGui::TextUnformatted(fmtClock(lc.firstSeen).c_str());
            if (ImGui::TableSetColumnIndex(CC_Path)) {
                textMuted(r.path.c_str());
                if (!r.path.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal))
                    ImGui::SetTooltip("%s", r.path.c_str());
            }
            ImGui::PopID();
        }
    }
    ImGui::EndTable();
}

void App::drawHosts() {
    const float avail = ImGui::GetContentRegionAvail().y;
    const float tableH = std::max(160 * scale, avail * 0.52f);
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                  ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_SizingFixedFit;
    if (ImGui::BeginTable("hosts_v2", HC_Count, flags, ImVec2(0, tableH))) {
        const float s = scale;
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableSetupColumn("IP", ImGuiTableColumnFlags_NoHide, 150 * s, HC_Ip);
        ImGui::TableSetupColumn("Host / Dominio", 0, 250 * s, HC_Host);
        ImGui::TableSetupColumn("Ámbito", 0, 65 * s, HC_Scope);
        ImGui::TableSetupColumn("Reputación", ImGuiTableColumnFlags_PreferSortDescending | repColumnFlags(), 90 * s, HC_Rep);
        ImGui::TableSetupColumn("VirusTotal", ImGuiTableColumnFlags_PreferSortDescending | vtColumnFlags(), 75 * s, HC_Vt);
        ImGui::TableSetupColumn("Organización", orgColumnFlags(), 190 * s, HC_Owner);
        ImGui::TableSetupColumn("País", orgColumnFlags(), 40 * s, HC_Country);
        ImGui::TableSetupColumn("Conexiones", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending,
                                85 * s, HC_Total);
        ImGui::TableSetupColumn("Activas", ImGuiTableColumnFlags_PreferSortDescending, 60 * s, HC_Active);
        ImGui::TableSetupColumn("Conex./min", ImGuiTableColumnFlags_PreferSortDescending, 80 * s, HC_Rate);
        ImGui::TableSetupColumn("Procesos", 0, 200 * s, HC_Procs);
        ImGui::TableSetupColumn("Puertos", 0, 150 * s, HC_Ports);
        ImGui::TableSetupColumn("Primera vez", 0, 80 * s, HC_First);
        ImGui::TableSetupColumn("Última vez", ImGuiTableColumnFlags_PreferSortDescending, 80 * s, HC_LastSeen);
        ImGui::TableSetupColumn("Interv. medio", 0, 95 * s, HC_Avg);
        ImGui::TableSetupColumn("Últ. intervalo", 0, 95 * s, HC_Last);
        ImGui::TableSetupColumn("Interv. mín", 0, 85 * s, HC_Min);
        tableHeaders();
        if (takeSort(hostSort_.col, hostSort_.asc, hostSort_.dirty)) sortHosts();

        const double now = viewNow();
        ImGuiListClipper clipper;
        clipper.Begin(int(hostRows_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const HostRow& r = hostRows_[size_t(i)];
                const HostStats& h = *r.h;
                ImGui::TableNextRow();
                const int sev = std::max(r.vt.severity(), r.rep.severity);
                if (sev == 2) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowMalicious);
                else if (sev == 1) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowSuspicious);
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(HC_Ip);
                if (sev == 2) rowStripe(kRowMalicious);
                else if (sev == 1) rowStripe(kRowSuspicious);
                if (ImGui::Selectable("##row", hasSelHost_ && selHost_ == h.ip,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                    selHost_ = h.ip;
                    hasSelHost_ = true;
                    dirty_ = true;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        setFilter(h.ipStr);
                        pendingTab_ = 0;
                    }
                }
                if (ImGui::BeginPopupContextItem("##ctx")) {
                    if (ImGui::MenuItem("Copiar IP")) ImGui::SetClipboardText(h.ipStr.c_str());
                    if (!r.name.empty() && ImGui::MenuItem("Copiar host / dominio")) ImGui::SetClipboardText(r.name.c_str());
                    if (ImGui::MenuItem("Ver sus conexiones")) {
                        setFilter(h.ipStr);
                        pendingTab_ = 0;
                    }
                    if (ImGui::MenuItem("Buscar IP en ipinfo.io")) openInBrowser("https://ipinfo.io/" + h.ipStr);
                    if (h.scope == Scope::Public) ipIntelMenu(h.ipStr);
                    ImGui::EndPopup();
                }
                ImGui::SameLine(0, 0);
                ImGui::TextUnformatted(h.ipStr.c_str());
                if (ImGui::TableSetColumnIndex(HC_Host)) ImGui::TextColored(kLink, "%s", r.name.c_str());
                if (ImGui::TableSetColumnIndex(HC_Scope)) textMuted(scopeName(h.scope));
                if (ImGui::TableSetColumnIndex(HC_Rep)) repCell(r.rep);
                if (ImGui::TableSetColumnIndex(HC_Vt)) vtCell(r.vt, true);
                if (ImGui::TableSetColumnIndex(HC_Owner)) ImGui::TextUnformatted(orgOf(r.rep, r.vt).c_str());
                if (ImGui::TableSetColumnIndex(HC_Country)) textMuted(countryOf(r.rep, r.vt).c_str());
                if (ImGui::TableSetColumnIndex(HC_Total)) textRightInt(h.total);
                if (ImGui::TableSetColumnIndex(HC_Active)) {
                    if (h.active) ImGui::PushStyleColor(ImGuiCol_Text, kGreen);
                    textRightInt(h.active);
                    if (h.active) ImGui::PopStyleColor();
                }
                if (ImGui::TableSetColumnIndex(HC_Rate)) textRightInt(h.ratePerMin(now));
                if (ImGui::TableSetColumnIndex(HC_Avg)) textRight(fmtDuration(h.avgInterval()));
                if (ImGui::TableSetColumnIndex(HC_Last)) textRight(fmtDuration(h.lastInterval()));
                if (ImGui::TableSetColumnIndex(HC_Min)) textRight(fmtDuration(h.minInterval));
                if (ImGui::TableSetColumnIndex(HC_Procs)) ImGui::TextUnformatted(h.procsStr.c_str());
                if (ImGui::TableSetColumnIndex(HC_Ports)) textMuted(h.portsStr.c_str());
                if (ImGui::TableSetColumnIndex(HC_First)) ImGui::TextUnformatted(fmtClock(h.firstSeen).c_str());
                if (ImGui::TableSetColumnIndex(HC_LastSeen)) ImGui::TextUnformatted(fmtClock(h.lastSeen).c_str());
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    const float leftW = ImGui::GetContentRegionAvail().x * 0.42f;
    ImGui::BeginChild("##bars", ImVec2(leftW, 0), ImGuiChildFlags_Border);
    drawHostBars();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##detail", ImVec2(0, 0), ImGuiChildFlags_Border);
    drawHostDetail();
    ImGui::EndChild();
}

void App::drawHostBars() {
    ImGui::AlignTextToFramePadding();
    sectionTitle("Top destinos");
    ImGui::SameLine();
    textMuted("por número de conexiones");
    ImGui::SameLine();
    {
        // chips alineados a la derecha del panel
        const ImGuiStyle& st = ImGui::GetStyle();
        const float w1 = ImGui::CalcTextSize("Agrupar por dominio").x, w2 = ImGui::CalcTextSize("Solo activos").x;
        const float chipsW = w1 + w2 + (14 * scale + st.FramePadding.x * 2) * 2 + st.ItemSpacing.x;
        const float x = ImGui::GetWindowContentRegionMax().x - chipsW;
        if (x > ImGui::GetCursorPosX()) ImGui::SetCursorPosX(x);
    }
    if (chip("Agrupar por dominio", &settings.groupByDomain, kAccent)) settingsChanged();
    ImGui::SameLine();
    if (chip("Solo activos", &settings.hostsOnlyActive, kGreen)) settingsChanged();
    const int n = int(barValues_.size());
    if (n == 0) {
        ImGui::TextDisabled("Todavía no hay conexiones con destino remoto.");
        return;
    }
    std::vector<const char*> labels;
    for (const auto& l : barLabels_) labels.push_back(l.c_str());
    ImPlot::PushStyleColor(ImPlotCol_FrameBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);  // el panel ya tiene borde
    if (ImPlot::BeginPlot("##topbars", ImVec2(-1, -1),
                          ImPlotFlags_NoLegend | ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect | ImPlotFlags_NoMouseText)) {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_AutoFit | ImPlotAxisFlags_NoSideSwitch,
                          ImPlotAxisFlags_AutoFit | ImPlotAxisFlags_NoGridLines | ImPlotAxisFlags_NoSideSwitch);
        ImPlot::SetupAxisTicks(ImAxis_Y1, 0, double(n - 1), n, labels.data());
        double maxv = 1;
        for (double v : barValues_) maxv = std::max(maxv, v);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, maxv * 1.18, ImPlotCond_Always);
        ImPlot::SetNextFillStyle(kAccent, 0.85f);
        ImPlot::PlotBars("Conexiones", barValues_.data(), n, 0.68, 0, ImPlotBarsFlags_Horizontal);
        for (int i = 0; i < n; ++i) {
            char txt[24];
            std::snprintf(txt, sizeof txt, "%.0f", barValues_[size_t(i)]);
            ImPlot::PlotText(txt, barValues_[size_t(i)], i, ImVec2(ImGui::CalcTextSize(txt).x * 0.5f + 6, 0));
        }
        if (ImPlot::IsPlotHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            const ImPlotPoint mp = ImPlot::GetPlotMousePos();
            const int idx = int(std::lround(mp.y));
            if (idx >= 0 && idx < n) {
                if (!barHosts_.empty()) {
                    selHost_ = barHosts_[size_t(idx)];
                    hasSelHost_ = true;
                    dirty_ = true;
                } else {
                    setFilter(barLabels_[size_t(idx)]);
                }
            }
        }
        ImPlot::EndPlot();
    }
    ImGui::PopStyleVar();
    ImPlot::PopStyleColor();
}

void App::drawHostDetail() {
    auto it = hasDetail_ ? tracker_.hosts.find(detailHost_) : tracker_.hosts.end();
    if (it == tracker_.hosts.end()) {
        ImGui::TextDisabled("Aquí aparecerá el detalle de cada host: tiempo entre peticiones,");
        ImGui::TextDisabled("procesos, puertos e historial de conexiones.");
        return;
    }
    const HostStats& h = it->second;
    const std::string name = resolver_.name(h.ip);

    // Cabecera en una sola línea: IP, ámbito y nombre.
    if (fonts.big) ImGui::PushFont(fonts.big);
    ImGui::TextUnformatted(h.ipStr.c_str());
    if (fonts.big) ImGui::PopFont();
    ImGui::SameLine();
    textMuted(scopeName(h.scope));
    if (!name.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(kLink, "%s", name.c_str());
    }
    if (!hasSelHost_) {
        ImGui::SameLine();
        ImGui::TextDisabled("(el de más conexiones)");
    }

    // Reputación y organización en una línea.
    if (settings.reputation && h.scope == Scope::Public) {
        const RepResult rep = rep_.lookup(h.ip);
        textMuted("Reputación:");
        ImGui::SameLine();
        repCell(rep);
        if (rep.severity > 0) {
            ImGui::SameLine();
            ImGui::TextColored(repColor(rep), "(%s)", rep.lists.c_str());
        }
        if (!rep.org.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(kMuted, "  AS%s %s", rep.asn.c_str(), rep.org.c_str());
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("AbuseIPDB")) openInBrowser("https://www.abuseipdb.com/check/" + h.ipStr);
    }

    // Veredicto de VirusTotal en una línea, solo si está activado.
    if (vtActive() && h.scope == Scope::Public) {
        const VtResult vt = vt_.ip(h.ip, h.ipStr);
        textMuted("VirusTotal:");
        ImGui::SameLine();
        if (vt.st == VtResult::St::Done) {
            ImGui::TextColored(vtColor(vt), "%s %d/%d", vt.verdict(), vt.malicious, vt.total());
            if (!vt.owner.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(kMuted, "%s %s", vt.owner.c_str(), vt.country.c_str());
            }
        } else {
            vtCell(vt);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Abrir en VirusTotal"))
            openInBrowser("https://www.virustotal.com/gui/ip-address/" + h.ipStr);
    }

    char histLabel[32];
    std::snprintf(histLabel, sizeof histLabel, "Historial (%zu)###hist", hostEventRows_.size());
    if (!ImGui::BeginTabBar("##detailtabs")) return;
    if (ImGui::BeginTabItem("Resumen")) {
        // Izquierda: estadísticas compactas. Derecha: histograma con todo el alto disponible.
        if (ImGui::BeginTable("##detailsplit", 2, ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("datos", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("grafica", ImGuiTableColumnFlags_WidthStretch, 1.15f);
            ImGui::TableNextColumn();
            if (ImGui::BeginTable("##hstats", 2, ImGuiTableFlags_None)) {
                ImGui::TableSetupColumn("k", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("Último intervalo").x);
                ImGui::TableSetupColumn("v", ImGuiTableColumnFlags_WidthStretch);
                auto row = [](const char* label, const std::string& value) {
                    ImGui::TableNextColumn();
                    textMuted(label);
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(value.c_str());
                };
                row("Conexiones", std::to_string(h.total) + "   (" + std::to_string(h.active) + " activas)");
                row("Último minuto", std::to_string(h.ratePerMin(viewNow())) + " conexiones");
                row("Intervalo medio", fmtDuration(h.avgInterval()));
                row("Último intervalo", fmtDuration(h.lastInterval()));
                row("Mín. / máx.", fmtDuration(h.minInterval) + " / " + fmtDuration(h.maxInterval));
                row("Primera / última", fmtClock(h.firstSeen) + " / " + fmtClock(h.lastSeen));
                row("Procesos", h.procsStr);
                if (ImGui::IsItemHovered() && !h.procsStr.empty()) ImGui::SetTooltip("%s", h.procsStr.c_str());
                row("Puertos", h.portsStr);
                if (ImGui::IsItemHovered() && !h.portsStr.empty()) ImGui::SetTooltip("%s", h.portsStr.c_str());
                ImGui::EndTable();
            }
            ImGui::TableNextColumn();
            const float plotH = std::max(110 * scale, ImGui::GetContentRegionAvail().y - ImGui::GetStyle().ItemSpacing.y);
            if (h.intervals.size() >= 2) {
                static std::vector<double> data;
                data.assign(h.intervals.begin(), h.intervals.end());
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
                if (ImPlot::BeginPlot("Tiempo entre peticiones", ImVec2(-1, plotH),
                                      ImPlotFlags_NoLegend | ImPlotFlags_NoMenus)) {
                    ImPlot::SetupAxes("segundos", nullptr, ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
                    ImPlot::SetNextFillStyle(kViolet, 0.8f);
                    ImPlot::PlotHistogram("Intervalos", data.data(), int(data.size()), ImPlotBin_Sturges);
                    ImPlot::EndPlot();
                }
                ImGui::PopStyleVar();
            } else {
                ImGui::TextDisabled("Aún no hay suficientes conexiones nuevas");
                ImGui::TextDisabled("a este host para calcular intervalos.");
            }
            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(histLabel)) {
        drawEventsTable("##hostevents", hostEventRows_, true);
        ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
}

void App::drawProcesses() {
    if (chip("Solo con conexiones activas", &settings.procsOnlyActive, kGreen)) settingsChanged();
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Doble clic: ver sus conexiones  \xC2\xB7  Clic derecho: más opciones");
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                  ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    if (!ImGui::BeginTable("procs", PC_Count, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Proceso", ImGuiTableColumnFlags_NoHide, 3.0f, PC_Name);
    ImGui::TableSetupColumn("PID", 0, 1.0f, PC_Pid);
    ImGui::TableSetupColumn("VirusTotal", ImGuiTableColumnFlags_PreferSortDescending | vtColumnFlags(), 1.1f, PC_Vt);
    ImGui::TableSetupColumn("TCP activas", ImGuiTableColumnFlags_PreferSortDescending, 1.2f, PC_Tcp);
    ImGui::TableSetupColumn("UDP activos", ImGuiTableColumnFlags_PreferSortDescending, 1.2f, PC_Udp);
    ImGui::TableSetupColumn("En escucha", ImGuiTableColumnFlags_PreferSortDescending, 1.1f, PC_Listen);
    ImGui::TableSetupColumn("Conexiones abiertas",
                            ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 1.5f, PC_Total);
    ImGui::TableSetupColumn("Hosts únicos", ImGuiTableColumnFlags_PreferSortDescending, 1.2f, PC_Hosts);
    ImGui::TableSetupColumn("Última actividad", ImGuiTableColumnFlags_PreferSortDescending, 1.3f, PC_Last);
    ImGui::TableSetupColumn("Ruta del ejecutable", 0, 5.0f, PC_Path);
    tableHeaders();
    if (takeSort(procSort_.col, procSort_.asc, procSort_.dirty)) sortProcs();

    ImGuiListClipper clipper;
    clipper.Begin(int(procRows_.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ProcRow& row = procRows_[size_t(i)];
            const ProcStats& p = *row.p;
            const std::string name = p.name.empty() ? "(desconocido)" : p.name;
            ImGui::TableNextRow();
            if (row.vt.severity() == 2) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowMalicious);
            else if (row.vt.severity() == 1) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kRowSuspicious);
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(PC_Name);
            if (ImGui::Selectable("##row", false,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                                      ImGuiSelectableFlags_AllowDoubleClick) &&
                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                setFilter(p.name.empty() ? pidText(p.pid) : p.name);
                pendingTab_ = 0;
            }
            if (ImGui::BeginPopupContextItem("##ctx")) {
                if (ImGui::MenuItem("Ver sus conexiones")) {
                    setFilter(p.name.empty() ? pidText(p.pid) : p.name);
                    pendingTab_ = 0;
                }
                if (ImGui::MenuItem("Copiar nombre")) ImGui::SetClipboardText(name.c_str());
                vtProcMenu(p.pid, p.name, row.vt, row.path);
                if (p.pid > 4 && ImGui::MenuItem("Terminar proceso...")) requestKill(p.pid, p.name);
                ImGui::EndPopup();
            }
            ImGui::SameLine(0, 0);
            ImGui::TextUnformatted(name.c_str());
            if (ImGui::TableSetColumnIndex(PC_Pid)) textRight(pidText(p.pid));
            if (ImGui::TableSetColumnIndex(PC_Vt)) vtCell(row.vt, true);
            if (ImGui::TableSetColumnIndex(PC_Path)) textMuted(row.path.c_str());
            if (ImGui::TableSetColumnIndex(PC_Tcp)) {
                ImGui::PushStyleColor(ImGuiCol_Text, p.activeTcp ? kTcp : kMuted);
                textRightInt(p.activeTcp);
                ImGui::PopStyleColor();
            }
            if (ImGui::TableSetColumnIndex(PC_Udp)) {
                ImGui::PushStyleColor(ImGuiCol_Text, p.activeUdp ? kUdp : kMuted);
                textRightInt(p.activeUdp);
                ImGui::PopStyleColor();
            }
            if (ImGui::TableSetColumnIndex(PC_Listen)) textRightInt(p.listening);
            if (ImGui::TableSetColumnIndex(PC_Total)) textRightInt(p.total);
            if (ImGui::TableSetColumnIndex(PC_Hosts)) textRightInt(static_cast<long long>(p.hosts.size()));
            if (ImGui::TableSetColumnIndex(PC_Last)) textRight(fmtClock(p.lastSeen));
            ImGui::PopID();
        }
    }
    ImGui::EndTable();
}

void App::drawActivity() {
    // Selector segmentado de la ventana de tiempo.
    ImGui::AlignTextToFramePadding();
    textMuted("Ventana de tiempo");
    ImGui::SameLine();
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(2 * scale, ImGui::GetStyle().ItemSpacing.y));
    for (int i = 0; i < 4; ++i) {
        const bool sel = settings.spanIndex == i;
        if (sel) {
            ImGui::PushStyleColor(ImGuiCol_Button, withAlpha(kAccent, 0.20f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, withAlpha(kAccent, 0.28f));
            ImGui::PushStyleColor(ImGuiCol_Border, withAlpha(kAccent, 0.55f));
        }
        if (ImGui::Button(kSpanNames[i], ImVec2(64 * scale, 0)) && !sel) {
            settings.spanIndex = i;
            ImGui::MarkIniSettingsDirty();
        }
        if (sel) ImGui::PopStyleColor(3);
        if (i < 3) ImGui::SameLine();
    }
    ImGui::PopStyleVar();
    const double now = viewNow();
    const double span = kSpans[settings.spanIndex];
    const int n = int(tsSeries_.size());
    const float plotH = std::max(170 * scale, ImGui::GetContentRegionAvail().y * 0.36f);

    auto plot = [&](const char* title, const std::vector<double>& a, const std::vector<double>& b) {
        double ymax = 1;
        for (int i = 0; i < n; ++i)
            if (tsSeries_[size_t(i)] >= now - span) ymax = std::max({ymax, a[size_t(i)], b[size_t(i)]});
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);  // el panel ya tiene borde
        if (ImPlot::BeginPlot(title, ImVec2(-1, -1), ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect)) {
            ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoHighlight, ImPlotAxisFlags_NoHighlight);
            ImPlot::SetupAxisScale(ImAxis_X1, ImPlotScale_Time);
            ImPlot::SetupAxisLimits(ImAxis_X1, now - span, now, ImPlotCond_Always);
            ImPlot::SetupAxisLimits(ImAxis_Y1, 0, ymax * 1.15, ImPlotCond_Always);
            ImPlot::SetupLegend(ImPlotLocation_NorthWest);
            if (n > 0) {
                ImPlot::SetNextFillStyle(kTcp, 0.18f);
                ImPlot::PlotShaded("TCP", tsSeries_.data(), a.data(), n);
                ImPlot::SetNextLineStyle(kTcp, 2.0f);
                ImPlot::PlotLine("TCP", tsSeries_.data(), a.data(), n);
                ImPlot::SetNextFillStyle(kUdp, 0.18f);
                ImPlot::PlotShaded("UDP", tsSeries_.data(), b.data(), n);
                ImPlot::SetNextLineStyle(kUdp, 2.0f);
                ImPlot::PlotLine("UDP", tsSeries_.data(), b.data(), n);
            }
            ImPlot::EndPlot();
        }
        ImGui::PopStyleVar();
    };

    if (ImGui::BeginTable("##plots", 2, ImGuiTableFlags_SizingStretchSame)) {
        ImGui::TableNextColumn();
        ImGui::BeginChild("##p1", ImVec2(0, plotH), ImGuiChildFlags_Border, ImGuiWindowFlags_NoScrollbar);
        plot("Nuevas conexiones por segundo", rateTcp_, rateUdp_);
        ImGui::EndChild();
        ImGui::TableNextColumn();
        ImGui::BeginChild("##p2", ImVec2(0, plotH), ImGuiChildFlags_Border, ImGuiWindowFlags_NoScrollbar);
        plot("Conexiones activas", actTcp_, actUdp_);
        ImGui::EndChild();
        ImGui::EndTable();
    }
    sectionTitle("Registro de eventos");
    ImGui::SameLine();
    ImGui::TextDisabled("%zu eventos, los más recientes primero  \xC2\xB7  usa el filtro de arriba", eventRows_.size());
    drawEventsTable("##events", eventRows_, false);
}

void App::drawEventsTable(const char* id, const std::vector<EventRow>& rows, bool compact) {
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_SizingStretchProp;
    const int cols = compact ? 6 : 9;
    if (!ImGui::BeginTable(id, cols, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Hora", 0, 1.2f);
    ImGui::TableSetupColumn("Evento", 0, 0.9f);
    ImGui::TableSetupColumn("Proto", 0, 0.6f);
    ImGui::TableSetupColumn("Proceso", 0, 1.6f);
    if (compact) {
        ImGui::TableSetupColumn("Puerto", 0, 0.8f);
    } else {
        ImGui::TableSetupColumn("PID", 0, 0.6f);
        ImGui::TableSetupColumn("Destino", 0, 2.0f);
        ImGui::TableSetupColumn("Host / Dominio", 0, 2.4f);
        ImGui::TableSetupColumn("Servicio", 0, 0.8f);
    }
    ImGui::TableSetupColumn("Detalle", 0, 1.6f);
    tableHeaders();
    ImGuiListClipper clipper;
    clipper.Begin(int(rows.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ConnEvent& e = *rows[size_t(i)].e;
            const Conn& c = e.c;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(fmtClockMs(e.ts).c_str());
            ImGui::TableNextColumn();
            pill(e.open ? "abierta" : "cerrada", e.open ? kGreen : kRed);
            ImGui::TableNextColumn();
            pill(protoName(c.proto), protoColor(c.proto));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(c.pname.empty() ? "?" : c.pname.c_str());
            if (compact) {
                ImGui::TableNextColumn();
                ImGui::Text("%u %s", unsigned(c.rport), connService(c));
            } else {
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(pidText(c.pid).c_str());
                ImGui::TableNextColumn();
                if (c.hasRemote()) ImGui::TextUnformatted(fmtAddr(c.rstr, c.rport, c.raddr.family == 6).c_str());
                else ImGui::TextColored(kMuted, "local %s", fmtAddr(c.lstr, c.lport, c.laddr.family == 6).c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(kLink, "%s", rows[size_t(i)].host.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(connService(c));
            }
            ImGui::TableNextColumn();
            textMuted(eventDetail(e).c_str());
        }
    }
    ImGui::EndTable();
}

// Franja fija en el borde inferior de la ventana, dibujada directamente (no ocupa layout).
void App::drawStatusBar() {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    const ImVec2 wp = win->Pos, ws = win->Size;
    const float barH = ImGui::GetTextLineHeight() + 12 * scale;
    const ImVec2 a(wp.x, wp.y + ws.y - barH), b(wp.x + ws.x, wp.y + ws.y);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(a, b, false);
    dl->AddRectFilled(a, b, ImGui::GetColorU32(ImGuiCol_ChildBg));
    dl->AddLine(a, ImVec2(b.x, a.y), ImGui::GetColorU32(ImGuiCol_Border));

    const float ty = a.y + (barH - ImGui::GetTextLineHeight()) * 0.5f;
    const float gap = 10 * scale;
    float x = a.x + ImGui::GetStyle().WindowPadding.x;
    char buf[256];
    auto text = [&](const ImVec4& col, const char* s) {
        dl->AddText(ImVec2(x, ty), ImGui::GetColorU32(col), s);
        x += ImGui::CalcTextSize(s).x;
    };
    auto sep = [&] {
        x += gap;
        dl->AddLine(ImVec2(x, ty + 3 * scale), ImVec2(x, ty + ImGui::GetTextLineHeight() - 3 * scale),
                    ImGui::GetColorU32(ImGuiCol_Border));
        x += gap + 1;
    };

    // Indicador de captura: en vivo / pausado.
    const bool paused = collector_.paused();
    const float r = 3.5f * scale;
    dl->AddCircleFilled(ImVec2(x + r, ty + ImGui::GetTextLineHeight() * 0.5f + 0.5f), r,
                        ImGui::GetColorU32(paused ? kVtWarn : kGreen));
    x += r * 2 + 7 * scale;
    text(paused ? kVtWarn : kText, paused ? "Pausado" : "En vivo");
    sep();
    std::snprintf(buf, sizeof buf, "NetAnalyzer %s", NETANALYZER_VERSION);
    text(kMuted, buf);
    sep();
    text(kMuted, collector_.sourceName());
    sep();
    std::snprintf(buf, sizeof buf, "%zu sockets  \xC2\xB7  muestreo %.1f ms  \xC2\xB7  %.0f fps", lastSockets_,
                  lastPollMs_, ImGui::GetIO().Framerate);
    text(kMuted, buf);
    if (const char* hint = privilegeHint(); *hint) {
        sep();
        text(kUdp, hint);
    }
    if (!lastError_.empty()) {
        sep();
        text(kRed, lastError_.c_str());
    }
    if (settings.reputation) {
        const Reputation::Status rs = rep_.status();
        sep();
        if (rs.lists == 0)
            std::snprintf(buf, sizeof buf, "Listas negras: %s", rs.downloading ? "descargando..." : "sin descargar");
        else
            std::snprintf(buf, sizeof buf, "Listas negras: %d (%zu entradas, %s)%s", rs.lists, rs.entries,
                          fmtClock(rs.updated).c_str(), rs.downloading ? ", actualizando..." : "");
        text(kMuted, buf);
        if (!rs.error.empty()) {
            sep();
            text(kVtWarn, rs.error.c_str());
        }
    }
    if (vtActive()) {
        const VirusTotal::Status vs = vt_.status();
        sep();
        std::snprintf(buf, sizeof buf, "VirusTotal: %zu en cola, %d/%d hoy", vs.queued, vs.usedToday, vs.perDay);
        text(kMuted, buf);
        if (!vs.error.empty()) {
            sep();
            text(kVtWarn, vs.error.c_str());
        }
    }
    if (!toast_.empty() && nowSeconds() < toastUntil_) {
        const float w = ImGui::CalcTextSize(toast_.c_str()).x;
        x = std::max(x + 2 * gap, b.x - ImGui::GetStyle().WindowPadding.x - w);
        text(toastError_ ? kRed : kGreen, toast_.c_str());
    }
    dl->PopClipRect();
}

void App::drawModals() {
    if (killRequested_) {
        ImGui::OpenPopup("Terminar proceso");
        killRequested_ = false;
    }
    if (ImGui::BeginPopupModal("Terminar proceso", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("¿Terminar %s (PID %d)?", killName_.empty() ? "el proceso" : killName_.c_str(), killPid_);
        textMuted("El programa se cerrará sin guardar nada.");
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Button, withAlpha(kRed, 0.75f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kRed);
        ImGui::PushStyleColor(ImGuiCol_Border, kRed);
        if (ImGui::Button("Terminar", ImVec2(120 * scale, 0))) {
            std::string err;
            if (killProcess(killPid_, err)) toast("Proceso " + std::to_string(killPid_) + " terminado");
            else toast(err, true);
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);
        ImGui::SameLine();
        if (ImGui::Button("Cancelar", ImVec2(120 * scale, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    drawVtSettings();
}

void App::applyVtSettings() {
    vt_.configure(settings.vtEnabled && settings.vtKey[0], settings.vtKey, settings.vtPerMinute, settings.vtPerDay);
    dirty_ = true;
}

void App::drawVtSettings() {
    if (vtSettingsRequested_) {
        ImGui::OpenPopup("VirusTotal");
        vtSettingsRequested_ = false;
    }
    ImGui::SetNextWindowSize(ImVec2(620 * scale, 0));
    if (!ImGui::BeginPopupModal("VirusTotal", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    ImGui::TextWrapped("Comprueba las IPs remotas públicas y los ejecutables de los procesos con red contra "
                       "VirusTotal, como hace Process Explorer. Las conexiones y procesos que algún antivirus "
                       "marca como maliciosos se resaltan en rojo, y los sospechosos en naranja.");
    ImGui::Spacing();
    ImGui::TextColored(kVtWarn, "Privacidad:");
    ImGui::SameLine();
    ImGui::TextWrapped("se envían a VirusTotal (Google) las IPs públicas a las que te conectas y el hash SHA-256 de "
                       "cada ejecutable. Nunca se sube ningún archivo. Las IPs privadas y locales no salen de tu equipo.");
    ImGui::Separator();

    bool changed = false;
    bool enabled = settings.vtEnabled;
    if (ImGui::Checkbox("Acepto y quiero activar la comprobación con VirusTotal", &enabled)) {
        settings.vtEnabled = enabled;
        changed = true;
    }

    ImGui::Spacing();
    ImGui::TextUnformatted("API key");
    ImGui::SameLine(140 * scale);
    ImGui::SetNextItemWidth(-90 * scale);
    if (ImGui::InputText("##vtkey", settings.vtKey, sizeof settings.vtKey,
                         vtShowKey_ ? ImGuiInputTextFlags_None : ImGuiInputTextFlags_Password))
        changed = true;
    ImGui::SameLine();
    ImGui::Checkbox("ver", &vtShowKey_);
    ImGui::TextDisabled("Gratis creando una cuenta en virustotal.com (Perfil > API key).");
    ImGui::SameLine();
    if (ImGui::SmallButton("Conseguir una API key")) openInBrowser("https://www.virustotal.com/gui/join-us");

    ImGui::TextUnformatted("Consultas / minuto");
    ImGui::SameLine(140 * scale);
    ImGui::SetNextItemWidth(120 * scale);
    if (ImGui::InputInt("##vtrpm", &settings.vtPerMinute)) {
        settings.vtPerMinute = std::clamp(settings.vtPerMinute, 1, 10000);
        changed = true;
    }
    ImGui::SameLine();
    ImGui::TextUnformatted("Consultas / día");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120 * scale);
    if (ImGui::InputInt("##vtday", &settings.vtPerDay, 50, 500)) {
        settings.vtPerDay = std::clamp(settings.vtPerDay, 1, 10000000);
        changed = true;
    }
    ImGui::TextDisabled("Plan gratuito: 4 por minuto y 500 al día. Los resultados se guardan en caché "
                        "(IPs 24 h, ejecutables 7 días).");

    if (settings.vtEnabled && !settings.vtKey[0]) ImGui::TextColored(kVtWarn, "Falta la API key.");
    const VirusTotal::Status st = vt_.status();
    if (settings.vtEnabled && settings.vtKey[0]) {
        ImGui::Text("En cola: %zu   Consultas hoy: %d/%d", st.queued, st.usedToday, st.perDay);
        if (!st.error.empty()) ImGui::TextColored(kVtWarn, "%s", st.error.c_str());
    }
    if (changed) {
        applyVtSettings();
        ImGui::MarkIniSettingsDirty();
    }

    ImGui::Separator();
    if (ImGui::Button("Vaciar caché", ImVec2(130 * scale, 0))) {
        vt_.clearCache();
        toast("Caché de VirusTotal vaciada");
    }
    ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - 120 * scale);
    if (ImGui::Button("Cerrar", ImVec2(120 * scale, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape))
        ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void App::requestKill(int pid, const std::string& name) {
    killPid_ = pid;
    killName_ = name;
    killRequested_ = true;
}

void App::toast(const std::string& msg, bool error) {
    toast_ = msg;
    toastError_ = error;
    toastUntil_ = nowSeconds() + 6;
}

void App::exportCsv() {
    static const char* tabNames[] = {"conexiones", "hosts", "procesos", "eventos"};
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%Y%m%d_%H%M%S", &tm);
    const std::string file = std::string("netanalyzer_") + tabNames[currentTab_] + "_" + stamp + ".csv";
    std::ofstream out(file, std::ios::binary);
    if (!out) {
        toast("No se pudo crear " + file, true);
        return;
    }
    out << "\xEF\xBB\xBF";  // BOM para que Excel lo abra como UTF-8
    auto row = [&out](std::initializer_list<std::string> fields) {
        bool first = true;
        for (const auto& f : fields) {
            if (!first) out << ',';
            out << csvField(f);
            first = false;
        }
        out << "\r\n";
    };
    const double now = viewNow();
    switch (currentTab_) {
        case 0:
            row({"Proto", "Proceso", "PID", "Local", "IP remota", "Puerto", "Servicio", "Host", "Estado", "Ambito",
                 "Reputacion", "Listas", "Organizacion", "VT_IP", "VT_IP_veredicto", "VT_proceso",
                 "VT_proceso_veredicto", "Duracion_s", "Desde", "Ruta"});
            for (const auto& r : connRows_) {
                const Conn& c = r.lc->c;
                row({protoName(c.proto), c.pname, pidText(c.pid), fmtAddr(c.lstr, c.lport, c.laddr.family == 6),
                     c.rstr, c.rport ? std::to_string(c.rport) : "", connService(c), r.host, c.status,
                     scopeName(ipScope(c.raddr)), r.rep.label(), r.rep.lists, orgOf(r.rep, r.vtIp),
                     r.vtIp.label(), r.vtIp.verdict(), r.vtProc.label(),
                     r.vtProc.verdict(), std::to_string(r.lc->age(now)), fmtClock(r.lc->firstSeen), r.path});
            }
            break;
        case 1:
            row({"IP", "Host", "Ambito", "Reputacion", "Listas", "AS", "VirusTotal", "VT_veredicto", "Organizacion",
                 "Pais", "Conexiones", "Activas", "Conex_min", "Intervalo_medio_s", "Ultimo_intervalo_s",
                 "Intervalo_min_s", "Intervalo_max_s", "Procesos", "Puertos", "Primera_vez", "Ultima_vez"});
            for (const auto& r : hostRows_) {
                const HostStats& h = *r.h;
                row({h.ipStr, r.name, scopeName(h.scope), r.rep.label(), r.rep.lists, r.rep.asn, r.vt.label(),
                     r.vt.verdict(), orgOf(r.rep, r.vt), countryOf(r.rep, r.vt),
                     std::to_string(h.total), std::to_string(h.active),
                     std::to_string(h.ratePerMin(now)), std::to_string(h.avgInterval()),
                     std::to_string(h.lastInterval()), std::to_string(h.minInterval), std::to_string(h.maxInterval),
                     h.procsStr, h.portsStr, fmtClock(h.firstSeen), fmtClock(h.lastSeen)});
            }
            break;
        case 2:
            row({"Proceso", "PID", "VirusTotal", "VT_veredicto", "SHA256", "Ruta", "TCP_activas", "UDP_activos",
                 "En_escucha", "Conexiones_abiertas", "Hosts_unicos"});
            for (const auto& r : procRows_) {
                const ProcStats& p = *r.p;
                row({p.name, pidText(p.pid), r.vt.label(), r.vt.verdict(), r.vt.sha256, r.path,
                     std::to_string(p.activeTcp), std::to_string(p.activeUdp), std::to_string(p.listening),
                     std::to_string(p.total), std::to_string(p.hosts.size())});
            }
            break;
        default:
            row({"Hora", "Evento", "Proto", "Proceso", "PID", "Destino", "Host", "Servicio", "Detalle"});
            for (const auto& r : eventRows_) {
                const ConnEvent& e = *r.e;
                const Conn& c = e.c;
                row({fmtClockMs(e.ts), e.open ? "abierta" : "cerrada", protoName(c.proto), c.pname, pidText(c.pid),
                     c.hasRemote() ? fmtAddr(c.rstr, c.rport, c.raddr.family == 6) : "", r.host, connService(c),
                     eventDetail(e)});
            }
            break;
    }
    std::error_code ec;
    toast("Exportado: " + std::filesystem::absolute(file, ec).string());
}

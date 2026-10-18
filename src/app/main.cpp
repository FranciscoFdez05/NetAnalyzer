// NetAnalyzer: explorador de conexiones de red en tiempo real (Windows, Linux, macOS).
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <dwmapi.h>
#endif
#define GL_SILENCE_DEPRECATION
#include <GLFW/glfw3.h>
#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#endif

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>

#include "app/app.h"
#include "core/http.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"

namespace {

void glfwError(int code, const char* desc) { std::fprintf(stderr, "GLFW %d: %s\n", code, desc); }

bool fileExists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

ImVec4 rgb(int r, int g, int b, float a = 1.0f) { return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a); }

// Tema oscuro sobrio: superficies grises neutras, un único color de acento y bordes finos.
void applyTheme(float scale) {
    ImGuiStyle& s = ImGui::GetStyle();
    ImGui::StyleColorsDark(&s);
    s.WindowRounding = 0;
    s.ChildRounding = 8;
    s.FrameRounding = 5;
    s.PopupRounding = 8;
    s.GrabRounding = 5;
    s.TabRounding = 0;
    s.ScrollbarRounding = 6;
    s.WindowPadding = ImVec2(14, 12);
    s.FramePadding = ImVec2(10, 6);
    s.ItemSpacing = ImVec2(8, 8);
    s.ItemInnerSpacing = ImVec2(6, 6);
    s.CellPadding = ImVec2(8, 4);
    s.ScrollbarSize = 12;
    s.WindowBorderSize = 0;
    s.ChildBorderSize = 1;
    s.PopupBorderSize = 1;
    s.FrameBorderSize = 1;
    s.TabBorderSize = 0;
    s.TabBarBorderSize = 1;
    s.SeparatorTextBorderSize = 1;
    s.SeparatorTextPadding = ImVec2(0, 4);
    s.WindowTitleAlign = ImVec2(0.5f, 0.5f);
    s.SelectableTextAlign = ImVec2(0, 0.5f);

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = rgb(226, 229, 235);
    c[ImGuiCol_TextDisabled] = rgb(120, 128, 143);
    c[ImGuiCol_WindowBg] = rgb(15, 17, 21);
    c[ImGuiCol_ChildBg] = rgb(21, 24, 30);
    c[ImGuiCol_PopupBg] = rgb(26, 30, 37);
    c[ImGuiCol_Border] = rgb(38, 43, 52);
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = rgb(25, 28, 35);
    c[ImGuiCol_FrameBgHovered] = rgb(31, 35, 44);
    c[ImGuiCol_FrameBgActive] = rgb(36, 41, 52);
    c[ImGuiCol_TitleBg] = rgb(21, 24, 30);
    c[ImGuiCol_TitleBgActive] = rgb(26, 30, 37);
    c[ImGuiCol_Button] = rgb(30, 34, 42);
    c[ImGuiCol_ButtonHovered] = rgb(40, 45, 56);
    c[ImGuiCol_ButtonActive] = rgb(48, 55, 69);
    c[ImGuiCol_Header] = rgb(76, 141, 255, 0.20f);
    c[ImGuiCol_HeaderHovered] = rgb(255, 255, 255, 0.045f);
    c[ImGuiCol_HeaderActive] = rgb(76, 141, 255, 0.28f);
    c[ImGuiCol_Tab] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabHovered] = rgb(255, 255, 255, 0.05f);
    c[ImGuiCol_TabSelected] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabSelectedOverline] = ImVec4(0, 0, 0, 0);  // el subrayado de acento lo dibuja App
    c[ImGuiCol_TabDimmed] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabDimmedSelected] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabDimmedSelectedOverline] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableHeaderBg] = rgb(24, 27, 34);
    c[ImGuiCol_TableBorderStrong] = rgb(38, 43, 52);
    c[ImGuiCol_TableBorderLight] = rgb(30, 34, 42);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = rgb(255, 255, 255, 0.018f);
    c[ImGuiCol_CheckMark] = rgb(76, 141, 255);
    c[ImGuiCol_SliderGrab] = rgb(76, 141, 255);
    c[ImGuiCol_SliderGrabActive] = rgb(110, 165, 255);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = rgb(50, 56, 68);
    c[ImGuiCol_ScrollbarGrabHovered] = rgb(64, 71, 86);
    c[ImGuiCol_ScrollbarGrabActive] = rgb(80, 89, 107);
    c[ImGuiCol_Separator] = rgb(38, 43, 52);
    c[ImGuiCol_SeparatorHovered] = rgb(76, 141, 255, 0.6f);
    c[ImGuiCol_SeparatorActive] = rgb(76, 141, 255);
    c[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TextSelectedBg] = rgb(76, 141, 255, 0.35f);
    c[ImGuiCol_NavHighlight] = rgb(76, 141, 255, 0.8f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.6f);
    s.ScaleAllSizes(scale);

    ImPlotStyle& ps = ImPlot::GetStyle();
    ImPlot::StyleColorsDark(&ps);
    ps.UseLocalTime = true;
    ps.Use24HourClock = true;
    ps.LineWeight = 2.0f;
    ps.PlotPadding = ImVec2(12 * scale, 12 * scale);
    ps.LabelPadding = ImVec2(6 * scale, 4 * scale);
    ps.LegendPadding = ImVec2(10 * scale, 8 * scale);
    ps.LegendInnerPadding = ImVec2(6 * scale, 4 * scale);
    ps.Colors[ImPlotCol_FrameBg] = ImVec4(0, 0, 0, 0);
    ps.Colors[ImPlotCol_PlotBg] = ImVec4(0, 0, 0, 0);
    ps.Colors[ImPlotCol_PlotBorder] = ImVec4(0, 0, 0, 0);
    ps.Colors[ImPlotCol_LegendBg] = rgb(26, 30, 37, 0.92f);
    ps.Colors[ImPlotCol_LegendBorder] = rgb(38, 43, 52);
    ps.Colors[ImPlotCol_AxisGrid] = rgb(255, 255, 255, 0.06f);
    ps.Colors[ImPlotCol_AxisText] = rgb(120, 128, 143);
    ps.Colors[ImPlotCol_TitleText] = rgb(226, 229, 235);
}

// Fuentes del sistema: normal, seminegrita (títulos), grande (cifras) y pequeña (etiquetas).
// En Windows se fusiona la fuente de iconos del sistema (Segoe Fluent Icons / MDL2 Assets).
void loadFonts(float px, float rasterScale, AppFonts& out) {
    static const ImWchar ranges[] = {0x0020, 0x00FF, 0x0100, 0x017F, 0x2013, 0x2026, 0x2190, 0x21FF, 0x2265, 0x2265,
                                     0x25CF, 0x25CF, 0};
    static const ImWchar iconRanges[] = {0xE700, 0xF8B3, 0};
    struct Family { const char* regular; const char* semibold; };
    const Family families[] = {
#if defined(_WIN32)
        {"C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\seguisb.ttf"},
        {"C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf"},
#elif defined(__APPLE__)
        {"/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"},
        {"/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"},
        {"/System/Library/Fonts/Helvetica.ttc", nullptr},
#else
        {"/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf"},
        {"/usr/share/fonts/noto/NotoSans-Regular.ttf", "/usr/share/fonts/noto/NotoSans-SemiBold.ttf"},
        {"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"},
        {"/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"},
        {"/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf", "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf"},
        {"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
         "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"},
        {"/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf", "/usr/share/fonts/truetype/ubuntu/Ubuntu-M.ttf"},
#endif
    };
    const char* iconFont = nullptr;
#if defined(_WIN32)
    if (fileExists("C:\\Windows\\Fonts\\SegoeIcons.ttf")) iconFont = "C:\\Windows\\Fonts\\SegoeIcons.ttf";
    else if (fileExists("C:\\Windows\\Fonts\\segmdl2.ttf")) iconFont = "C:\\Windows\\Fonts\\segmdl2.ttf";
#endif
    ImGuiIO& io = ImGui::GetIO();
    io.FontGlobalScale = 1.0f / rasterScale;
    auto add = [&](const char* path, float size, bool icons) -> ImFont* {
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        ImFont* f = io.Fonts->AddFontFromFileTTF(path, size * rasterScale, &cfg, ranges);
        if (f && icons && iconFont) {
            ImFontConfig ic;
            ic.MergeMode = true;
            ic.OversampleH = 2;
            ic.GlyphOffset = ImVec2(0, size * 0.12f * rasterScale);
            ic.GlyphMinAdvanceX = size * rasterScale;
            if (io.Fonts->AddFontFromFileTTF(iconFont, size * 0.92f * rasterScale, &ic, iconRanges)) out.icons = true;
        }
        return f;
    };
    for (const Family& fam : families) {
        if (!fileExists(fam.regular)) continue;
        const char* bold = fam.semibold && fileExists(fam.semibold) ? fam.semibold : fam.regular;
        out.normal = add(fam.regular, px, true);
        if (!out.normal) continue;
        out.bold = add(bold, px, true);
        out.big = add(bold, px * 1.6f, false);
        out.label = add(bold, px * 0.85f, false);
        return;
    }
    out.icons = false;
    auto def = [&](float size) {
        ImFontConfig cfg;
        cfg.SizePixels = 13.0f * size / 16.0f * rasterScale;
        return io.Fonts->AddFontDefault(&cfg);
    };
    out.normal = def(px);
    out.bold = out.normal;
    out.big = def(px * 1.6f);
    out.label = out.normal;
}

#ifdef _WIN32
// Barra de título oscura (Windows 10 20H1+ / 11), a juego con la interfaz.
void setDarkTitleBar(GLFWwindow* win) {
    HWND hwnd = glfwGetWin32Window(win);
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    const COLORREF caption = RGB(15, 17, 21), text = RGB(226, 229, 235), border = RGB(38, 43, 52);
    DwmSetWindowAttribute(hwnd, 35 /* DWMWA_CAPTION_COLOR (Windows 11) */, &caption, sizeof caption);
    DwmSetWindowAttribute(hwnd, 36 /* DWMWA_TEXT_COLOR */, &text, sizeof text);
    DwmSetWindowAttribute(hwnd, 34 /* DWMWA_BORDER_COLOR */, &border, sizeof border);
}
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
// Icono de la ventana en Linux, dibujado por código con la misma geometría que el logo
// (tools/make_logo.py). En Windows lo pone GLFW desde el recurso GLFW_ICON del .exe.
void setWindowIcon(GLFWwindow* win) {
    const int N = 64, SS = 4;  // tamaño y supermuestreo por eje
    static unsigned char px[N * N * 4];
    const float kRadius = 0.225f, kHubR = 0.105f, kSatR = 0.078f, kSatDist = 0.315f, kLinkW = 0.044f;
    const float kRingR = 0.315f, kRingW = 0.03f, kRingAlpha = 0.38f;
    const float angles[3] = {-150.0f, -30.0f, 90.0f};
    float sats[3][2];
    for (int i = 0; i < 3; ++i) {
        const float r = angles[i] * 3.14159265f / 180.0f;
        sats[i][0] = 0.5f + std::cos(r) * kSatDist;
        sats[i][1] = 0.5f + std::sin(r) * kSatDist;
    }
    auto segDist = [](float x, float y, const float* b) {
        const float ax = 0.5f, ay = 0.5f, dx = b[0] - ax, dy = b[1] - ay;
        float t = ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy);
        t = t < 0 ? 0 : (t > 1 ? 1 : t);
        return std::hypot(ax + t * dx - x, ay + t * dy - y);
    };
    for (int y = 0; y < N; ++y) {
        for (int x = 0; x < N; ++x) {
            float acc[4] = {0, 0, 0, 0};  // premultiplicado
            for (int sy = 0; sy < SS; ++sy) {
                for (int sx = 0; sx < SS; ++sx) {
                    const float u = (x + (sx + 0.5f) / SS) / N, v = (y + (sy + 0.5f) / SS) / N;
                    // cuadrado redondeado
                    const float qx = std::max(std::fabs(u - 0.5f) - (0.5f - kRadius), 0.0f);
                    const float qy = std::max(std::fabs(v - 0.5f) - (0.5f - kRadius), 0.0f);
                    if (qx * qx + qy * qy > kRadius * kRadius) continue;
                    const float t = (u + v) * 0.5f;
                    float c[3] = {64 + (124 - 64) * t, 140 + (92 - 140) * t, 255 + (250 - 255) * t};
                    auto blend = [&c](float r, float g, float b, float a) {
                        c[0] += (r - c[0]) * a;
                        c[1] += (g - c[1]) * a;
                        c[2] += (b - c[2]) * a;
                    };
                    const float dc = std::hypot(u - 0.5f, v - 0.5f);
                    if (std::fabs(dc - kRingR) <= kRingW * 0.5f) blend(255, 255, 255, kRingAlpha);
                    bool white = dc <= kHubR;
                    for (int i = 0; i < 3 && !white; ++i) white = segDist(u, v, sats[i]) <= kLinkW * 0.5f;
                    if (white) blend(255, 255, 255, 1);
                    for (int i = 0; i < 3; ++i)
                        if (std::hypot(u - sats[i][0], v - sats[i][1]) <= kSatR)
                            i == 2 ? blend(74, 222, 128, 1) : blend(255, 255, 255, 1);
                    acc[0] += c[0];
                    acc[1] += c[1];
                    acc[2] += c[2];
                    acc[3] += 1;
                }
            }
            unsigned char* p = px + (y * N + x) * 4;
            for (int i = 0; i < 3; ++i) p[i] = acc[3] > 0 ? (unsigned char)(acc[i] / acc[3]) : 0;
            p[3] = (unsigned char)(255.0f * acc[3] / (SS * SS));
        }
    }
    GLFWimage img{N, N, px};
    glfwSetWindowIcon(win, 1, &img);
}
#endif

}  // namespace

int main(int argc, char** argv) {
    int startTab = -1;  // --tab=0..3 abre directamente en esa pestaña
    for (int i = 1; i < argc; ++i)
        if (std::strncmp(argv[i], "--tab=", 6) == 0) startTab = std::atoi(argv[i] + 6);
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    glfwSetErrorCallback(glfwError);
    if (!glfwInit()) return 1;

#if defined(__APPLE__)
    const char* glsl = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    const char* glsl = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
    glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);
    glfwWindowHint(GLFW_SAMPLES, 4);
    glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);  // se muestra ya ajustada y centrada
    const char* title = "NetAnalyzer v" NETANALYZER_VERSION " - Explorador de conexiones de red";
    // 1720x950: caben todas las columnas de la tabla de conexiones sin desplazamiento horizontal.
    GLFWwindow* win = glfwCreateWindow(1720, 950, title, nullptr, nullptr);
    if (!win) {
        glfwWindowHint(GLFW_SAMPLES, 0);
        win = glfwCreateWindow(1720, 950, title, nullptr, nullptr);
    }
    if (!win) {
        glfwTerminate();
        return 1;
    }
    // En pantallas pequeñas se limita al área de trabajo del monitor y se centra.
    if (GLFWmonitor* mon = glfwGetPrimaryMonitor()) {
        int mx = 0, my = 0, mw = 0, mh = 0;
        glfwGetMonitorWorkarea(mon, &mx, &my, &mw, &mh);
        int ww = 0, wh = 0, fl = 0, ft = 0, fr = 0, fb = 0;
        glfwGetWindowSize(win, &ww, &wh);
        glfwGetWindowFrameSize(win, &fl, &ft, &fr, &fb);
        if (mw > 0 && mh > 0) {
            ww = std::min(ww, mw - fl - fr - 20);
            wh = std::min(wh, mh - ft - fb - 20);
            glfwSetWindowSize(win, ww, wh);
            glfwSetWindowPos(win, mx + (mw - ww - fl - fr) / 2 + fl, my + (mh - wh - ft - fb) / 2 + ft);
        }
    }
#ifdef _WIN32
    setDarkTitleBar(win);
#endif
    glfwShowWindow(win);
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);  // vsync: animación fluida sin gastar CPU de más
#if !defined(_WIN32) && !defined(__APPLE__)
    setWindowIcon(win);
#endif

    float xs = 1, ys = 1;
    glfwGetWindowContentScale(win, &xs, &ys);
#if defined(__APPLE__)
    const float layoutScale = 1.0f;  // macOS trabaja en puntos; el framebuffer ya es Retina
    const float rasterScale = xs;
#else
    const float layoutScale = xs;
    const float rasterScale = 1.0f;
#endif

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    static const std::string iniPath = configFilePath();
    io.IniFilename = iniPath.c_str();

    applyTheme(layoutScale);
    AppFonts fonts;
    loadFonts(16.0f * layoutScale, rasterScale, fonts);

    ImGui_ImplGlfw_InitForOpenGL(win, true);
    ImGui_ImplOpenGL3_Init(glsl);

    // El Resolver no se destruye a propósito: sus hilos pueden seguir dentro de
    // getnameinfo() al salir y el SO los termina junto con el proceso.
    Resolver* resolver = new Resolver();
    httpInit();
    VirusTotal* vt = new VirusTotal();  // mismo motivo: puede haber una petición HTTPS en curso al salir
    Reputation* rep = new Reputation();
    {
        CollectorThread collector([] { glfwPostEmptyEvent(); });  // despierta la interfaz al llegar datos
        App app(collector, *resolver, *vt, *rep);
        app.scale = layoutScale;
        app.fonts = fonts;
        if (startTab >= 0 && startTab <= 3) app.selectTab(startTab);

        double lastInput = 0, lastFrame = 0;
        while (!glfwWindowShouldClose(win)) {
            // Con interacción reciente se dibuja a ~60 fps (durmiendo entre frames, sin depender
            // del vsync del driver, que en algunos equipos hace espera activa); en reposo se
            // espera a eventos o a datos nuevos, así la CPU queda casi a cero.
            if (glfwGetTime() - lastInput < 1.5) {
                // Los eventos de ratón despiertan la espera antes de tiempo: se sigue esperando
                // (procesando eventos) hasta que toque el siguiente frame.
                const double deadline = lastFrame + 1.0 / 60.0;
                glfwPollEvents();
                for (double rem = deadline - glfwGetTime(); rem > 0.0005; rem = deadline - glfwGetTime())
                    glfwWaitEventsTimeout(rem);
            } else {
                glfwWaitEventsTimeout(0.25);
            }

            if (glfwGetWindowAttrib(win, GLFW_ICONIFIED)) {
                app.poll();  // las estadísticas siguen acumulándose minimizado
                glfwWaitEventsTimeout(0.5);
                continue;
            }

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();
            // El movimiento del ratón solo cuenta si está sobre la ventana: con la ventana
            // enfocada, GLFW reporta la posición aunque el ratón esté en otro monitor.
            const bool hovered = glfwGetWindowAttrib(win, GLFW_HOVERED) != 0;
            if ((hovered && (io.MouseDelta.x != 0 || io.MouseDelta.y != 0 || io.MouseWheel != 0 ||
                             io.MouseWheelH != 0)) ||
                ImGui::IsAnyMouseDown() || io.InputQueueCharacters.Size > 0 || ImGui::IsAnyItemActive())
                lastInput = glfwGetTime();

            app.frame();

            ImGui::Render();
            int w = 0, h = 0;
            glfwGetFramebufferSize(win, &w, &h);
            glViewport(0, 0, w, h);
            glClearColor(15 / 255.0f, 17 / 255.0f, 21 / 255.0f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(win);
            lastFrame = glfwGetTime();
        }
        ImGui::SaveIniSettingsToDisk(io.IniFilename);
        io.IniFilename = nullptr;  // el handler de ajustes apunta a `app`, que muere aquí
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(win);
    glfwTerminate();
    return 0;
}

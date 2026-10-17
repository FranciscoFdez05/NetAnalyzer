// NetAnalyzer: explorador de conexiones de red en tiempo real (Windows, Linux, macOS).
#ifdef _WIN32
#include <winsock2.h>
#endif
#define GL_SILENCE_DEPRECATION
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>

#include "app.h"
#include "http.h"
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

void applyTheme(float scale) {
    ImGuiStyle& s = ImGui::GetStyle();
    ImGui::StyleColorsDark(&s);
    s.WindowRounding = 0;
    s.ChildRounding = 8;
    s.FrameRounding = 6;
    s.PopupRounding = 6;
    s.GrabRounding = 6;
    s.TabRounding = 6;
    s.ScrollbarRounding = 8;
    s.WindowPadding = ImVec2(12, 10);
    s.FramePadding = ImVec2(10, 5);
    s.ItemSpacing = ImVec2(8, 7);
    s.CellPadding = ImVec2(7, 3);
    s.ScrollbarSize = 13;
    s.WindowBorderSize = 0;
    s.ChildBorderSize = 1;
    s.PopupBorderSize = 1;
    s.FrameBorderSize = 1;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = rgb(230, 232, 238);
    c[ImGuiCol_TextDisabled] = rgb(139, 147, 165);
    c[ImGuiCol_WindowBg] = rgb(20, 22, 27);
    c[ImGuiCol_ChildBg] = rgb(27, 30, 37);
    c[ImGuiCol_PopupBg] = rgb(34, 38, 48);
    c[ImGuiCol_Border] = rgb(44, 49, 60);
    c[ImGuiCol_FrameBg] = rgb(36, 40, 50);
    c[ImGuiCol_FrameBgHovered] = rgb(46, 52, 65);
    c[ImGuiCol_FrameBgActive] = rgb(54, 62, 80);
    c[ImGuiCol_Button] = rgb(38, 43, 54);
    c[ImGuiCol_ButtonHovered] = rgb(49, 56, 72);
    c[ImGuiCol_ButtonActive] = rgb(59, 69, 96);
    c[ImGuiCol_Header] = rgb(43, 74, 122, 0.85f);
    c[ImGuiCol_HeaderHovered] = rgb(43, 74, 122, 0.55f);
    c[ImGuiCol_HeaderActive] = rgb(53, 90, 150);
    c[ImGuiCol_Tab] = rgb(27, 30, 37);
    c[ImGuiCol_TabHovered] = rgb(49, 56, 72);
    c[ImGuiCol_TabActive] = rgb(43, 74, 122);
    c[ImGuiCol_TabUnfocused] = rgb(27, 30, 37);
    c[ImGuiCol_TabUnfocusedActive] = rgb(38, 55, 85);
    c[ImGuiCol_TableHeaderBg] = rgb(30, 34, 43);
    c[ImGuiCol_TableBorderStrong] = rgb(44, 49, 60);
    c[ImGuiCol_TableBorderLight] = rgb(36, 40, 50);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.025f);
    c[ImGuiCol_CheckMark] = rgb(79, 157, 255);
    c[ImGuiCol_SliderGrab] = rgb(79, 157, 255);
    c[ImGuiCol_SliderGrabActive] = rgb(110, 175, 255);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = rgb(58, 64, 77);
    c[ImGuiCol_ScrollbarGrabHovered] = rgb(72, 80, 96);
    c[ImGuiCol_ScrollbarGrabActive] = rgb(90, 100, 120);
    c[ImGuiCol_Separator] = rgb(44, 49, 60);
    c[ImGuiCol_TextSelectedBg] = rgb(79, 157, 255, 0.35f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.55f);
    s.ScaleAllSizes(scale);

    ImPlotStyle& ps = ImPlot::GetStyle();
    ImPlot::StyleColorsDark(&ps);
    ps.UseLocalTime = true;
    ps.Use24HourClock = true;
    ps.LineWeight = 2.0f;
    ps.Colors[ImPlotCol_FrameBg] = ImVec4(0, 0, 0, 0);
    ps.Colors[ImPlotCol_PlotBg] = rgb(15, 17, 21);
    ps.Colors[ImPlotCol_PlotBorder] = rgb(44, 49, 60);
    ps.Colors[ImPlotCol_LegendBg] = rgb(27, 30, 37, 0.9f);
    ps.Colors[ImPlotCol_AxisGrid] = rgb(255, 255, 255, 0.07f);
}

// Fuente del sistema con soporte de acentos; si no hay ninguna se usa la integrada.
ImFont* loadFonts(float px, float bigPx, float rasterScale, ImFont** big) {
    static const ImWchar ranges[] = {0x0020, 0x00FF, 0x0100, 0x017F, 0x2013, 0x2026, 0x2190, 0x21FF, 0x2265, 0x2265, 0};
    const char* candidates[] = {
#if defined(_WIN32)
        "C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\arial.ttf",
#elif defined(__APPLE__)
        "/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
#else
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf", "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
#endif
    };
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.OversampleH = 2;
    for (const char* path : candidates) {
        if (!fileExists(path)) continue;
        ImFont* normal = io.Fonts->AddFontFromFileTTF(path, px * rasterScale, &cfg, ranges);
        if (!normal) continue;
        *big = io.Fonts->AddFontFromFileTTF(path, bigPx * rasterScale, &cfg, ranges);
        io.FontGlobalScale = 1.0f / rasterScale;
        return normal;
    }
    ImFontConfig def;
    def.SizePixels = 13.0f * px / 16.0f * rasterScale;
    ImFont* normal = io.Fonts->AddFontDefault(&def);
    def.SizePixels = 13.0f * bigPx / 16.0f * rasterScale;
    *big = io.Fonts->AddFontDefault(&def);
    io.FontGlobalScale = 1.0f / rasterScale;
    return normal;
}

#ifndef __APPLE__
// Icono de la ventana dibujado por código (sin ficheros extra): nodos de red sobre fondo azul.
void setWindowIcon(GLFWwindow* win) {
    const int N = 48;
    static unsigned char px[N * N * 4];
    const float nodes[4][2] = {{14, 14}, {34, 12}, {24, 34}, {38, 32}};
    auto distSeg = [](float x, float y, const float* a, const float* b) {
        float dx = b[0] - a[0], dy = b[1] - a[1];
        float t = ((x - a[0]) * dx + (y - a[1]) * dy) / (dx * dx + dy * dy);
        t = t < 0 ? 0 : (t > 1 ? 1 : t);
        float ex = a[0] + t * dx - x, ey = a[1] + t * dy - y;
        return ex * ex + ey * ey;
    };
    for (int y = 0; y < N; ++y) {
        for (int x = 0; x < N; ++x) {
            unsigned char* p = px + (y * N + x) * 4;
            const float cx = x - 23.5f, cy = y - 23.5f;
            const bool inside = cx * cx + cy * cy <= 23.5f * 23.5f;
            p[0] = 40; p[1] = 110; p[2] = 220; p[3] = inside ? 255 : 0;
            if (!inside) continue;
            bool white = false;
            for (int i = 0; i < 4 && !white; ++i) {
                const float dx = x - nodes[i][0], dy = y - nodes[i][1];
                white = dx * dx + dy * dy <= 20;
            }
            const int edges[4][2] = {{0, 1}, {0, 2}, {1, 3}, {2, 3}};
            for (int i = 0; i < 4 && !white; ++i)
                white = distSeg(float(x), float(y), nodes[edges[i][0]], nodes[edges[i][1]]) <= 2.2f;
            if (white) p[0] = p[1] = p[2] = 255;
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
    glfwShowWindow(win);
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);  // vsync: animación fluida sin gastar CPU de más
#ifndef __APPLE__
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
    ImFont* big = nullptr;
    loadFonts(16.0f * layoutScale, 25.0f * layoutScale, rasterScale, &big);

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
        app.fontBig = big;
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
            glClearColor(0.078f, 0.086f, 0.106f, 1.0f);
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

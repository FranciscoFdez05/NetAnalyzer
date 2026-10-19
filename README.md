<p align="center">
  <img src="resources/logo.png" alt="NetAnalyzer" width="128">
</p>

<h1 align="center">NetAnalyzer</h1>

<p align="center">
  <a href="https://github.com/FranciscoFdez05/NetAnalyzer/releases/latest"><img src="https://img.shields.io/github/v/release/FranciscoFdez05/NetAnalyzer?label=versi%C3%B3n" alt="Última versión"></a>
  <a href="https://github.com/FranciscoFdez05/NetAnalyzer/actions/workflows/build.yml"><img src="https://github.com/FranciscoFdez05/NetAnalyzer/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C" alt="C++17">
  <img src="https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-0078D4" alt="Windows | Linux | macOS">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue" alt="License: MIT"></a>
</p>

Explorador de conexiones de red en tiempo real, al estilo de Process Explorer / TCPView,
para **Windows, Linux y macOS**. Escrito en **C++17** con una interfaz gráfica acelerada
por GPU ([Dear ImGui](https://github.com/ocornut/imgui) + [ImPlot](https://github.com/epezent/implot) + [GLFW](https://www.glfw.org/)).
El resultado es un único ejecutable, sin instalar nada más.

**Versión 1.0.0** ([cambios](CHANGELOG.md)). Probada en Windows 10/11; las versiones de Linux y
macOS aún no se han compilado ni probado en esos sistemas.

## Qué muestra

- **Conexiones**: cada socket TCP/UDP con proceso, PID, origen, IP y puerto remoto,
  servicio (https, dns, quic...), host o dominio, estado, ámbito (pública/privada/loopback),
  duración y hora de inicio. Las nuevas aparecen en **verde** y las que se cierran en **rojo**.
- **Hosts / IPs**: ranking de las IPs y dominios a los que más conexiones se hacen,
  conexiones por minuto y **tiempo entre peticiones** (medio, último y mínimo), con
  gráfica de barras de los principales destinos (por IP o agrupados por dominio).
  El panel de detalle incluye un histograma de los intervalos y el historial de ese host.
- **Procesos**: qué programas usan la red, cuántas conexiones TCP/UDP tienen y a cuántos hosts hablan.
- **Actividad**: gráficas en vivo de conexiones nuevas por segundo y conexiones activas
  (TCP y UDP), y un registro de eventos de apertura y cierre con el intervalo o la duración de cada una.

- **Reputación** (sin API key, activada por defecto): marca en **rojo** o **naranja** las IPs
  que aparecen en listas negras públicas y muestra la **organización** propietaria de cada IP.
- **VirusTotal** (opcional, como en Process Explorer): marca en **rojo** las conexiones,
  IPs y procesos que los antivirus de VirusTotal detectan como maliciosos, y en **naranja**
  los sospechosos (ver más abajo).

Otras funciones: filtro global (`-texto` excluye), menú contextual (copiar IP o host,
filtrar, buscar la IP en ipinfo.io o VirusTotal, terminar el proceso), exportación a CSV
de la pestaña actual y ajustes que se recuerdan entre sesiones.

## Reputación de IPs (sin API key)

La casilla **Reputación** comprueba cada IP pública contra listas negras públicas. Las listas
se descargan al arrancar y cada 6 horas (`netanalyzer_listas.txt` en la carpeta de ajustes) y se
consultan en local: es instantáneo, no tiene límites y **ninguna de tus IPs sale del equipo**.

| Lista | Contenido | Resultado |
|---|---|---|
| [Feodo Tracker](https://feodotracker.abuse.ch/) (abuse.ch) | Servidores de control de botnets | malicioso |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Redes secuestradas o de ciberdelincuentes | malicioso |
| [IPsum](https://github.com/stamparm/ipsum) nivel 3 | IPs presentes en 3 o más listas negras | malicioso |
| [Emerging Threats](https://rules.emergingthreats.net/) | Equipos comprometidos | sospechoso |
| [CINS Army](https://cinsscore.com/), [blocklist.de](https://www.blocklist.de/) | Atacantes y escáneres | sospechoso |
| [Tor](https://check.torproject.org/torbulkexitlist) | Nodos de salida de Tor | Tor |

"sin reportes" significa que la IP no está en ninguna lista, lo que no garantiza que sea segura.
Para juzgarla ayuda la columna **Organización**, que se obtiene por DNS del servicio gratuito de
[Team Cymru](https://www.team-cymru.com/ip-asn-mapping) (igual que el DNS inverso, envía la IP
consultada a su servidor DNS). El clic derecho permite abrir cualquier IP en AbuseIPDB o VirusTotal.

## VirusTotal

Se activa con el botón **VirusTotal** (arriba a la derecha). Hace falta una API key gratuita:
crea una cuenta en [virustotal.com](https://www.virustotal.com/gui/join-us) y cópiala desde tu perfil.

- **Procesos**: se calcula el SHA-256 de cada ejecutable con conexiones y se consulta su
  informe. La columna muestra `motores que lo detectan / motores totales` (p. ej. `0/72`).
  "desconocido" significa que VirusTotal nunca lo ha visto, lo que no implica que sea malo.
- **IPs**: se consulta la reputación de cada IP pública. Además se obtiene la **organización**
  propietaria (CLOUDFLARENET, GOOGLE, AMAZON...) y el país, útiles cuando la IP no tiene nombre.
- **Colores**: rojo si 3 o más motores la marcan como maliciosa; naranja si 1 o 2 lo hacen o
  alguno la marca como sospechosa; verde si ninguno. Escribe `malicioso` o `sospechoso` en el
  filtro para ver solo esas filas.
- **Privacidad**: está desactivado por defecto. Solo se envían las IPs **públicas** y los
  **hashes**; nunca se sube ningún archivo. Las IPs privadas y locales no salen del equipo.
- **Límites**: el plan gratuito permite 4 consultas por minuto y 500 al día, así que hay una
  cola, y los resultados se guardan en caché (IPs 24 h, ejecutables 7 días). Si tienes un plan
  de pago puedes subir los límites en la misma ventana.
- La API key se guarda en tu archivo de ajustes (`%APPDATA%\NetAnalyzer.ini`,
  `~/.config/netanalyzer.ini` o `~/Library/Preferences/netanalyzer.ini`), y la caché en
  `netanalyzer_virustotal.tsv`, en la misma carpeta.

| Atajo | Acción |
|---|---|
| `Ctrl+F` | Ir al filtro |
| `Ctrl+P` | Pausar / reanudar |
| `F5` | Muestrear ahora |
| `Ctrl+S` | Exportar la pestaña actual a CSV |

## De dónde salen los datos

En vez de ejecutar comandos y leer su texto, se usa directamente la API del sistema que
hay detrás de cada uno. Es más rápido (unos 1–15 ms por muestreo) y más estable.

| SO | API usada | Equivale a |
|---|---|---|
| Windows | `GetExtendedTcpTable` / `GetExtendedUdpTable` (iphlpapi) | `Get-NetTCPConnection` |
| Linux | `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` | `sudo netstat -tunap` |
| macOS | `libproc` (`proc_pidfdinfo`) | `sudo lsof -i -P -n`, `netstat -anv` |

## Descargar

Los ejecutables de Windows, Linux y macOS se generan automáticamente con GitHub Actions y se
publican en [Releases](https://github.com/FranciscoFdez05/NetAnalyzer/releases): descomprime y
ejecuta `NetAnalyzer` (o `NetAnalyzer.exe`). En Linux necesitas además `libcurl` (viene instalado
en casi todas las distribuciones). En macOS el ejecutable no está firmado por Apple: la primera vez
ábrelo con clic derecho > Abrir, o quítale la marca de cuarentena con
`xattr -d com.apple.quarantine NetAnalyzer`.

## Compilar

Hace falta **CMake ≥ 3.20** y un compilador C++17. La primera vez, CMake descarga GLFW,
Dear ImGui e ImPlot (con versión y hash SHA-256 fijos). El ejecutable queda en `build/Release`.

### Windows
Requiere Visual Studio 2022 o posterior con la carga de trabajo *Desarrollo para el escritorio con C++*.
```bat
build.bat
build\Release\NetAnalyzer.exe
```
No hace falta ser administrador: Windows muestra todas las conexiones con su PID.

### Linux
```sh
# Debian/Ubuntu
sudo apt install build-essential cmake libgl-dev libx11-dev libxrandr-dev libxinerama-dev \
                 libxcursor-dev libxi-dev libwayland-dev libxkbcommon-dev wayland-protocols \
                 libcurl4-openssl-dev
# Fedora
sudo dnf install gcc-c++ cmake mesa-libGL-devel libX11-devel libXrandr-devel libXinerama-devel \
                 libXcursor-devel libXi-devel wayland-devel libxkbcommon-devel wayland-protocols-devel \
                 libcurl-devel

./build.sh
./build/Release/NetAnalyzer
```
Sin root solo se identifican los procesos de tu usuario. Para verlos todos hay dos opciones:
```sh
sudo -E ./build/Release/NetAnalyzer          # como root, conservando tu sesión gráfica
# o, sin ejecutar la interfaz como root:
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep ./build/Release/NetAnalyzer
./build/Release/NetAnalyzer
```

### macOS
```sh
xcode-select --install     # compilador
brew install cmake
./build.sh
sudo ./build/Release/NetAnalyzer   # sin sudo solo se ven los procesos de tu usuario
```

### Tests

Los tests se compilan junto con la aplicación (desactívalos con `-DNETANALYZER_TESTS=OFF`):
```sh
ctest --test-dir build -C Release --output-on-failure
```

### Opciones de línea de comandos

| Opción | Efecto |
|---|---|
| `--tab=N` | Abre directamente la pestaña N (0 Conexiones, 1 Hosts, 2 Procesos, 3 Actividad) |

## Cómo se mide el "tiempo entre peticiones"

NetAnalyzer consulta la tabla de sockets del sistema cada cierto tiempo (por defecto 1 s,
configurable de 0,25 a 10 s). Compara cada muestreo con el anterior: los sockets nuevos son
**aperturas** y los que desaparecen, **cierres**. El intervalo de un host es el tiempo entre
una apertura y la siguiente hacia esa misma IP.

- La resolución es la del muestreo. Las conexiones que nacen y mueren entre dos muestreos
  no se ven, y las que se abren en el mismo muestreo cuentan como *simultáneas*.
- Las conexiones que ya existían al arrancar se marcan con `>=` porque su duración real es desconocida.

## Limitaciones

- **UDP**: casi todo el tráfico UDP (DNS, QUIC/HTTP3, mDNS) usa sockets *no conectados*, que
  no tienen IP remota fija. Se ven activando "Escuchas / UDP sin destino", pero sin destino.
  Ver cada datagrama requiere captura de paquetes (Npcap/libpcap).
- **Nombres**: en Windows se consulta primero la caché DNS del sistema, que da el dominio
  realmente pedido. Muchos navegadores (Chrome, Edge, Vivaldi, Firefox) usan su propio
  resolvedor o DNS cifrado (DoH) y no la rellenan. En ese caso, y en Linux y macOS, se usa el
  DNS inverso (PTR), que muchas IPs (Cloudflare, Google...) no tienen o que devuelve nombres
  de infraestructura (`*.1e100.net`, `*.amazonaws.com`).
- **URLs**: con HTTPS la ruta completa va cifrada y ninguna herramienta de este tipo puede verla.
  Como mucho se puede obtener el dominio, capturando el SNI del TLS.

## Estructura

```
NetAnalyzer/
├── CMakeLists.txt        Configuración principal (versión, opciones, subdirectorios)
├── cmake/
│   ├── Dependencies.cmake    GLFW, Dear ImGui, ImPlot y nlohmann/json (versión y hash fijos)
│   └── CompilerWarnings.cmake  Avisos comunes del compilador
├── src/
│   ├── app/              Interfaz gráfica (depende de ImGui)
│   ├── core/             Lógica independiente de la interfaz (biblioteca netanalyzer_core)
│   └── platform/         Lectura de sockets específica de cada SO
├── tests/                Tests automáticos (ctest)
├── resources/            Recursos del ejecutable (versión de Windows)
└── build.bat / build.sh  Compilación en un paso
```

Los includes van relativos a `src/` (`#include "core/tracker.h"`), así queda claro de qué capa viene cada
cabecera. `core` no depende de `app`, y los tests solo enlazan con `core`.

| Archivo | Contenido |
|---|---|
| `src/app/main.cpp` | Ventana, tema, fuentes y bucle de dibujo (redibuja solo cuando hay datos o interacción) |
| `src/app/app.cpp/.h` | Interfaz: tablas, gráficas, filtros, menús, exportación CSV |
| `src/core/tracker.cpp/.h` | Convierte muestreos en eventos y estadísticas por host y proceso |
| `src/core/collector.cpp/.h` | Hilo de muestreo e interfaz común de los recolectores |
| `src/platform/collector_{win,linux,macos}.cpp` | Lectura de sockets específica de cada SO |
| `src/core/resolver.cpp/.h` | IP → nombre en segundo plano (caché DNS de Windows + DNS inverso) |
| `src/core/reputation.cpp/.h` | Listas negras públicas + organización/AS por DNS (Team Cymru) |
| `src/core/virustotal.cpp/.h` | Cliente de VirusTotal: cola, límites, caché en disco |
| `src/core/http.cpp/.h` | HTTPS mínimo (WinHTTP en Windows, libcurl en Linux/macOS) |
| `src/core/sha256.cpp/.h` | SHA-256 de ejecutables (BCrypt en Windows, portable en el resto) |
| `src/core/common.cpp/.h` | Tipos (`Conn`, `IpAddr`) y utilidades de formato |
| `resources/netanalyzer.rc.in` | Versión que aparece en Propiedades del `.exe` |
| `tests/tests.cpp` | Tests automáticos (`ctest`) |

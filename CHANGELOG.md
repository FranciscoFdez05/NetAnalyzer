# Changelog

## 1.0.0 — 2026-10-18

Primera versión pública.

### Monitorización
- Conexiones TCP/UDP en tiempo real con proceso, PID, origen, destino, servicio, estado y duración,
  leídas de la API nativa de cada sistema (GetExtendedTcpTable en Windows, `/proc/net` en Linux,
  libproc en macOS). Las nuevas se resaltan en verde y las que se cierran, en rojo.
- Pestaña **Hosts / IPs**: ranking de destinos, conexiones por minuto y tiempo entre peticiones
  (medio, último, mínimo y máximo), con gráfica de barras e histograma de intervalos por host.
- Pestaña **Procesos** y pestaña **Actividad** (gráficas en vivo y registro de eventos).
- Nombres de host por DNS inverso y, en Windows, desde la caché DNS del sistema.

### Seguridad
- **Reputación sin API key**: listas negras públicas (abuse.ch Feodo, Spamhaus DROP, IPsum,
  Emerging Threats, CINS Army, blocklist.de, Tor) consultadas en local, y organización/AS de
  cada IP vía Team Cymru.
- **VirusTotal** opcional (API key gratuita del usuario): veredicto de IPs y de ejecutables por
  SHA-256, con cola, límites del plan gratuito y caché en disco. Nunca sube archivos.

### Interfaz
- Interfaz acelerada por GPU (Dear ImGui + ImPlot): menos del 1 % de CPU en reposo.
- Filtro global, ordenación por cualquier columna, menú contextual (copiar, filtrar, AbuseIPDB,
  VirusTotal, terminar proceso), exportación a CSV y ajustes persistentes.

### Calidad
- Compila sin avisos con `/W4` (MSVC) y `-Wall -Wextra`.
- 136 comprobaciones automáticas (`ctest`): direcciones IP, tracker de conexiones, SHA-256 con los
  vectores oficiales FIPS 180-4, análisis de listas negras, veredictos y el recolector real del SO.

### Estado por plataforma
- **Windows 10/11**: probado.
- **Linux y macOS**: el código está escrito contra sus APIs nativas, pero esta versión no se ha
  compilado ni probado todavía en esos sistemas.

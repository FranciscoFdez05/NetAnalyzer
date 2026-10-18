# Changelog

## Sin publicar

### Interfaz
- Rediseño visual: tema oscuro neutro con un único color de acento, barra de título oscura en
  Windows, fuente seminegrita para títulos y cabeceras, e iconos del sistema (Segoe Fluent Icons)
  en los botones cuando están disponibles.
- Barra de herramientas reorganizada: filtro con icono de búsqueda y botón para limpiarlo, y los
  filtros de vista como interruptores ("chips") agrupados en *Mostrar* y *Análisis*.
- Tarjetas de métricas rediseñadas, con minigráficas que se escalan a su rango para que se vean las
  variaciones.
- Tablas más legibles: protocolo como etiqueta, estado TCP con punto de color, filas nuevas,
  cerradas o maliciosas marcadas con una franja lateral y un tinte más suave.
- Pestañas con subrayado de acento, selector segmentado de la ventana de tiempo y barra de estado
  fija con indicador "En vivo" / "Pausado".
- Logo nuevo (`tools/make_logo.py`): icono del `.exe`, de la ventana y de la barra de tareas.
- Columna **Ruta del ejecutable** en Conexiones y Procesos, sin necesidad de VirusTotal; también
  en el filtro, el menú contextual y el CSV.
- En Hosts, las columnas de intervalos pasan al final de la tabla.

### Compilación
- El ejecutable se genera en `build/Release` en lugar de en la raíz del proyecto.

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

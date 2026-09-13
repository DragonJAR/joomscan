# OWASP JoomScan

[![Licencia](https://img.shields.io/badge/licencia-GPLv3-red.svg)](LICENSE)
[![Versión](https://img.shields.io/badge/versi%C3%B3n-0.0.8--2026.refresh-green.svg)](https://github.com/DragonJAR/joomscan)
[![Perl](https://img.shields.io/badge/perl-5.x-yellow.svg)](https://www.perl.org)
[![Soporte Joomla](https://img.shields.io/badge/joomla-1.0%20a%206.1.3-blue.svg)](https://www.joomla.org)
[![Pruebas](https://img.shields.io/badge/pruebas-89%20pasadas-brightgreen.svg)](t/)
[![Mantenido por](https://img.shields.io/badge/mantenido%20por-DragonJAR%20SAS-orange.svg)](https://www.DragonJAR.org)
[![English](https://img.shields.io/badge/read%20in-English-blue.svg)](README.md)

> Escáner de vulnerabilidades y auditor de seguridad moderno para Joomla. Combina detección de versiones multietapa (Joomla 1.0 a 6.1.3), calibración de línea base para eliminar falsos positivos, correlación matemática de CVEs por SemVer, auditoría concurrente de extensiones y reportes HTML interactivos offline bajo una arquitectura modular y DRY.

---

## 🎯 Qué hace OWASP JoomScan

OWASP JoomScan automatiza la detección de vulnerabilidades, auditoría de configuraciones y descubrimiento de superficie de ataque en instalaciones Joomla CMS:

- **Detección multietapa de versiones (Joomla 1.0 a 6.1.3)**: 6 capas jerárquicas (manifests XML, registros JSON de assets, paquetes de idioma dinámicos, generadores meta/RSS, archivos legacy y firmas de assets front-end) con resolución automática en la raíz del dominio para sitios montados en subcarpetas o proxies inversos.
- **Eliminación sistemática de falsos positivos**: Calibra la respuesta base del servidor para neutralizar páginas genéricas con status HTTP 200 (soft-404). Los archivos sensibles, respaldos y paneles administrativos exigen validación sintáctica de firmas (`class JConfig`, `[core]`, variables de entorno, tokens de login) antes de aceptar un código 200.
- **Correlación matemática de CVEs por SemVer**: Contrasta la versión detectada contra más de 220 boletines oficiales del core de Joomla, incluyendo los boletines de agosto de 2026 (e.g. `CVE-2026-73373`, `CVE-2026-73337`, `CVE-2026-71574` que afectaban hasta 6.1.2 y fueron corregidos en 6.1.3).
- **Seguimiento de ciclo de vida y fin de soporte (EOL)**: Matriz completa de soporte desde Joomla 1.x hasta las ramas activas Serie 5 (5.4.8) y Serie 6 (6.1.3, con soporte de seguridad hasta 2028/2029).
- **Auditoría de componentes y extensiones**: Descubrimiento pasivo mediante análisis del DOM y enumeración activa de alto rendimiento mediante un pool concurrente de procesos de trabajo (`run_pool()`).
- **Detección de archivos sensibles y metadatos VCS**: Localiza archivos `.env`, metadatos de Git/SVN, volcados de configuración de base de datos, registros de errores y asistentes de restauración sin limpiar (e.g. Akeeba Kickstart).
- **Detección de WAF y línea base de cabeceras de seguridad**: Identifica los principales cortafuegos web (Cloudflare, ModSecurity, Sucuri, Incapsula) y audita cabeceras recomendadas de mitigación (HSTS, CSP, X-Frame-Options, Permissions-Policy).
- **Dashboard interactivo offline moderno**: Genera un informe HTML autocontenido (sin llamadas a CDNs externas), responsive y con puntuación dinámica de postura de seguridad en 5 dimensiones, además de salidas en consola y JSON para pipelines de CI/CD.
- **Control de tráfico y evasión**: Retardo configurable entre peticiones, rotación aleatoria de User-Agents, soporte de proxies (HTTP/HTTPS/SOCKS) y retroceso automático ante respuestas 429/503 por límite de peticiones.

> **Importante:** OWASP JoomScan está diseñado para evaluaciones de seguridad autorizadas, ejercicios de penetración y auditorías defensivas. Asegúrese siempre de contar con la autorización explícita correspondiente antes de escanear cualquier infraestructura objetivo.

---

## 📦 Instalación

### Opción 1: Instalación nativa

Clone el repositorio y verifique las dependencias de Perl:

```bash
git clone https://github.com/DragonJAR/joomscan.git
cd joomscan
perl joomscan.pl --help
```

Si su sistema requiere instalar módulos de Perl:

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install perl libwww-perl liblwp-protocol-https-perl

# CPAN (Alternativa)
cpan install LWP::UserAgent LWP::Protocol::https
```

### Opción 2: Instalación mediante Docker

Ejecute JoomScan en un contenedor aislado sin necesidad de instalar dependencias en el sistema host:

```bash
# Construir la imagen de Docker
docker build -t dragonjar/joomscan .

# Ejecutar el escaneo montando la carpeta local de reportes
docker run -it --rm -v $(pwd)/reports:/home/joomscan/reports dragonjar/joomscan -u https://example.com
```

---

## ⚙️ Requisitos previos

| Dependencia | Versión mínima | Propósito |
|-------------|----------------|-----------|
| **Perl** | 5.20+ | Entorno de ejecución principal |
| **LWP::UserAgent** | 6.00+ | Motor HTTP/HTTPS con reutilización de conexiones |
| **LWP::Protocol::https** | Cualquiera | Soporte de cifrado TLS/SSL para objetivos HTTPS |
| **Docker** | 20.10+ | Opcional para despliegue encapsulado en contenedores |

### Verificación

Ejecute la suite de pruebas automatizadas para confirmar que todos los motores de sondeo, parsers de SemVer, algoritmos de calibración y bases de datos operan correctamente:

```bash
prove -I. t/
```

Las 6 suites y 89 aserciones deben completarse exitosamente.

---

## 🛡️ Arquitectura y flujo de verificación

El motor implementa una canalización de verificación no destructiva bajo el principio DRY:

```
[URL Objetivo]
      │
      ▼
[1. Calibración de línea base] ──► Sondea token aleatorio; extrae título y longitud de catch-all
      │
      ▼
[2. Detección por capas]       ──► Consulta capas 1 a 6 con fallback al dominio raíz (Early Exit)
      │
      ▼
[3. Validación sintáctica]     ──► Exige firmas reales (JConfig, [core], .env, formularios)
      │
      ▼
[4. Correlación SemVer CVE]    ──► Evalúa tuplas de versión vs intervalos oficiales (Joomla 1.0 - 6.1.3)
      │
      ▼
[5. Generación de informe]     ──► Emite reportes en texto, JSON y dashboard HTML interactivo offline
```

1. **Calibración de línea base**: Realiza una petición con una ruta aleatoria inexistente. Si el servidor responde con código 200 (portal catch-all), JoomScan guarda el título y la variación de tamaño para descartar soft-404.
2. **Detección por capas**: Extrae la versión de Joomla iniciando en los manifests principales (`administrator/manifests/files/joomla.xml`, `media/system/joomla.asset.json`) y descendiendo hacia paquetes de idioma o firmas de assets.
3. **Validación de firmas**: Rechaza páginas HTML genéricas; los hallazgos críticos requieren la presencia verificada de estructuras y cabeceras auténticas.
4. **Evaluación SemVer**: Contrasta las versiones detectadas contra límites matemáticos (`<`, `<=`, `a-b`), evitando falsos positivos derivados de comparaciones de texto plano.
5. **Generación de informe**: Calcula las métricas de postura defensiva y ensambla un panel HTML autocontenido con planes de remediación a 24 horas.

---

## 🚀 Ejemplos de uso

### Ejemplo 1: Auditoría estándar (raíz o subdirectorio)

Escanea un objetivo, detecta la versión con fallback al dominio raíz y genera el informe HTML moderno:

```bash
perl joomscan.pl -u https://example.com/cms
```

### Ejemplo 2: Auditoría completa con enumeración concurrente de extensiones

Enumera componentes instalados utilizando 10 procesos concurrentes:

```bash
perl joomscan.pl -u https://example.com --enumerate-components --threads 10
```

### Ejemplo 3: Evaluación de bajo perfil y evasión

Auditoría a través de un proxy de intercepción (e.g. Burp Suite), rotación de User-Agent y retardo entre peticiones:

```bash
perl joomscan.pl -u https://example.com -r --delay 0.5 --proxy http://127.0.0.1:8080
```

### Ejemplo 4: Integración en CI/CD y salida JSON sin banners

Ejecución en modo silencioso redirigiendo los resultados estructurados en formato JSON a STDOUT:

```bash
perl joomscan.pl -u https://example.com --silent --json > resultado.json
```

### Ejemplo 5: Escaneo masivo de objetivos

Auditoría por lotes de múltiples objetivos especificados línea a línea en un archivo de texto:

```bash
perl joomscan.pl -m objetivos.txt --threads 5
```

---

## 📊 Opciones de línea de comandos

| Opción | Corta | Parámetro | Descripción |
|--------|-------|-----------|-------------|
| `--url` | `-u` | `<URL>` | URL o dominio de Joomla a auditar. |
| `--mass` | `-m` | `<archivo>` | Audita por lotes los objetivos listados en un archivo de texto. |
| `--enumerate-components` | `-ec` | Ninguno | Enumera componentes instalados mediante diccionario. |
| `--joomla-version` | `-jv` | Ninguno | Detecta la versión de Joomla y finaliza inmediatamente. |
| `--threads` | `-t` | `<int>` | Número de procesos concurrentes (por defecto: `5`). |
| `--delay` | Ninguno | `<seg>` | Retardo entre peticiones HTTP en segundos (e.g. `0.5`). |
| `--cookie` | Ninguno | `<str>` | Asigna la cabecera Cookie en las peticiones HTTP. |
| `--user-agent` | `-a` | `<str>` | Especifica una cadena User-Agent personalizada. |
| `--random-agent` | `-r` | Ninguno | Asigna un User-Agent aleatorio para cada petición. |
| `--proxy` | Ninguno | `<URL>` | Enruta el tráfico mediante proxy HTTP, HTTPS o SOCKS. |
| `--timeout` | Ninguno | `<seg>` | Tiempo límite de conexión HTTP en segundos (por defecto: `60`). |
| `--json` | Ninguno | Ninguno | Emite los resultados del escaneo en formato JSON a STDOUT. |
| `--silent` | Ninguno | Ninguno | Suprime banners y salidas de escaneo intermedias en la consola. |
| `--no-report` | `-nr` | Ninguno | Omite la generación de archivos de reporte en disco. |
| `--version` | Ninguno | Ninguno | Muestra la versión de JoomScan y finaliza. |
| `--help` | `-h` | Ninguno | Muestra la pantalla de ayuda con las opciones de uso. |

---

## 🧪 Pruebas automatizadas

JoomScan incluye una suite de pruebas automatizadas que valida la estabilidad y precisión de los motores de detección:

```bash
# Ejecutar todas las pruebas
prove -I. t/

# Ejecutar archivos de prueba específicos en modo detallado
perl -I. t/01_semver.t
perl -I. t/02_eol.t
perl -I. t/06_probe_helpers.t
```

La cobertura de pruebas contempla:
- **Lógica de SemVer** (`t/01_semver.t`): Comparación de rangos, límites de versión y casos de borde.
- **Ciclo de vida y EOL** (`t/02_eol.t`): Estados de soporte y ciclo de vida desde Joomla 1.0 hasta 6.1.3.
- **Opciones de CLI** (`t/03_cli.t`): Validación de banderas y parámetros de terminal.
- **Integridad de base de datos** (`t/04_db_integrity.t`): Sintaxis y estructura de diccionarios de vulnerabilidades.
- **Concurrencia de pool de trabajadores** (`t/05_pool.t`): Segmentación en paralelo, manejo de errores y pipes IPC.
- **Funciones de sondeo y verificación** (`t/06_probe_helpers.t`): Calibración de soft-404, validación sintáctica de archivos sensibles, fallback a la raíz y detección de Joomla 6.1.3.

---

## 👥 Autores y mantenimiento

### 👨‍💻 Autores originales y líderes del proyecto
- **Mohammad Reza Espargham** ([@rezesp](https://twitter.com/rezesp))
- **Ali Razmjoo** ([@Ali_Razmjo0](https://twitter.com/Ali_Razmjo0))

### 🛠️ Reactivación y mantenimiento del proyecto
**DragonJAR SAS** — [https://www.DragonJAR.org](https://www.DragonJAR.org)

[Expertos en servicios de seguridad informática, validación proactiva y seguridad ofensiva.](https://www.dragonjar.org/servicios-de-seguridad-informatica)

### 🌐 Recursos oficiales
- [Página oficial del proyecto en OWASP](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project)
- [Repositorio en GitHub](https://github.com/DragonJAR/joomscan)
- [Seguimiento de incidentes (Issues)](https://github.com/DragonJAR/joomscan/issues)
- [Video de introducción en YouTube](https://www.youtube.com/watch?v=Ik2CJ9LkuoI)

---

## 📄 Licencia

Este proyecto está distribuido bajo la licencia **GNU General Public License v3.0** — consulte el archivo [LICENSE](LICENSE) para más detalles.

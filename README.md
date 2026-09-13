# OWASP JoomScan

[![License](https://img.shields.io/badge/license-GPLv3-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.8--refresh-green.svg)](https://github.com/DragonJAR/joomscan)
[![Perl](https://img.shields.io/badge/perl-5.x-yellow.svg)](https://www.perl.org)
[![Joomla Support](https://img.shields.io/badge/joomla-1.0%20to%206.x-blue.svg)](https://www.joomla.org)
[![Author](https://img.shields.io/badge/maintainer-DragonJAR-orange.svg)](https://www.dragonjar.org)
[![Español](https://img.shields.io/badge/read%20in-Espa%C3%B1ol-blue.svg)](README.es.md)

> Modern, reliable Joomla vulnerability scanner and security auditor. Combines multi-tier version detection (Joomla 1.0 to 6.x), server baseline calibration to eliminate false positives, mathematical SemVer CVE matching, concurrent extension auditing, and responsive offline HTML reporting into a lightweight, DRY architecture.

---

## 🎯 What OWASP JoomScan Does

OWASP JoomScan automates vulnerability detection, configuration auditing, and attack surface discovery in Joomla CMS deployments:

- **Multi-Tier Version Detection (Joomla 1.0 to 6.x)**: 6 hierarchical detection layers (XML manifests, asset JSON, dynamic language packs, meta/feed generators, legacy assets, and core frontend signatures) with automated root-domain fallback for alias and reverse-proxy mount points.
- **False-Positive Elimination**: Server baseline calibration detects catch-all HTTP 200 responses (soft-404s). Sensitive files, backups, and administrator portals require strict syntactic signature validation (`class JConfig`, `[core]`, environment variables, login tokens) rather than trusting HTTP status codes alone.
- **Mathematical SemVer CVE Matching**: Evaluates exact target versions against 220+ official Joomla core advisories, including the latest 2026 security bulletins (up to Joomla 6.1.3).
- **Component & Extension Auditing**: Passive discovery via DOM assets and active high-speed dictionary enumeration powered by a fork-based worker pool.
- **Sensitive Files & VCS Metadata Detection**: Discovers `.env` files, Git/SVN metadata, database configuration leaks, log files, and uncleaned backup archives (e.g. Akeeba Kickstart).
- **Firewall & Security Headers Baseline**: Detects leading Web Application Firewalls (Cloudflare, ModSecurity, Sucuri, Incapsula) and audits hardening headers (HSTS, CSP, X-Frame-Options, Permissions-Policy).
- **Modern Offline Dashboard**: Generates a self-contained, responsive, single-file HTML report with dynamic security posture scores across 5 dimensions, alongside text and JSON outputs for CI/CD pipelines.
- **Evasion & Traffic Control**: Configurable delay, random User-Agents, proxy support, and automatic backoff when encountering HTTP 429/503 rate limits.

> **Important:** OWASP JoomScan is designed for authorized security assessments, penetration testing, and defensive auditing. Always ensure you have explicit authorization before scanning target infrastructure.

---

## 📦 Installation

### Option 1: Native Installation

Clone the repository and verify Perl dependencies:

```bash
git clone https://github.com/DragonJAR/joomscan.git
cd joomscan
perl joomscan.pl --help
```

If your system lacks required Perl modules:

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install perl libwww-perl liblwp-protocol-https-perl

# CPAN (Alternative)
cpan install LWP::UserAgent LWP::Protocol::https
```

### Option 2: Docker Installation

Run JoomScan in an isolated container without installing host dependencies:

```bash
# Build the Docker image
docker build -t dragonjar/joomscan .

# Run scan with local reports directory mounted
docker run -it --rm -v $(pwd)/reports:/home/joomscan/reports dragonjar/joomscan -u https://example.com
```

---

## ⚙️ Prerequisites

| Dependency | Minimum Version | Purpose |
|------------|-----------------|---------|
| **Perl** | 5.20+ | Core runtime environment |
| **LWP::UserAgent** | 6.00+ | HTTP/HTTPS engine with connection reuse |
| **LWP::Protocol::https** | Any | TLS/SSL support for encrypted targets |
| **Docker** | 20.10+ | Optional containerized deployment |

### Verification

Run the automated test suite to ensure all probe engines, SemVer parsers, baseline algorithms, and databases are operational:

```bash
prove -I. t/
```

All 6 test files and 89 assertions should pass cleanly.

---

## 🛡️ Architecture & Verification Workflow

The engine follows a strict DRY, non-destructive verification pipeline:

```
[Target URL]
     │
     ▼
[1. Baseline Calibration] ──► Probe random token; fingerprint catch-all title & length
     │
     ▼
[2. Multi-Tier Detection]  ──► Query Tiers 1-6 with root domain fallback (Early Exit)
     │
     ▼
[3. Signature Validation] ──► Enforce syntax parsing (JConfig, [core], .env, form tokens)
     │
     ▼
[4. SemVer CVE Matching]  ──► Evaluate version tuples vs advisories (Joomla 1.0 - 6.x)
     │
     ▼
[5. Report Generation]    ──► Emit text, JSON, and self-contained offline HTML dashboard
```

1. **Baseline Calibration**: Probes a randomized non-existent path. If the server responds with HTTP 200 (portal catch-all), JoomScan establishes baseline title and byte variance to filter out soft-404 false positives.
2. **Multi-Tier Detection**: Resolves the Joomla version starting from definitive manifests (`administrator/manifests/files/joomla.xml`, `media/system/joomla.asset.json`) and gracefully falls back to language packs or frontend assets.
3. **Signature Validation**: Rejects generic HTML pages for sensitive paths; genuine findings must exhibit structurally authentic headers or tokens.
4. **SemVer Evaluation**: Matches identified versions against mathematical intervals (`<`, `<=`, `a-b`), preventing regex false matches.
5. **Report Generation**: Computes dimension metrics and produces a single-file offline HTML dashboard containing 24-hour remediation steps.

---

## 🚀 Usage Examples

### Example 1: Standard Audit (Root or Subpath)

Scans a target, detects version with root-domain fallback, and generates a modern HTML report:

```bash
perl joomscan.pl -u https://uftm.edu.br/proplan
```

### Example 2: Full Audit with Extension Enumeration & Concurrency

Enumerate installed components using 10 concurrent worker threads:

```bash
perl joomscan.pl -u https://example.com --enumerate-components --threads 10
```

### Example 3: Evasion & Low-Noise Assessment

Scan through an interception proxy (e.g. Burp Suite) with random User-Agents and request throttling:

```bash
perl joomscan.pl -u https://example.com -r --delay 0.5 --proxy http://127.0.0.1:8080
```

### Example 4: CI/CD Pipeline & Headless JSON Output

Run silently without console banners and emit structured JSON output to STDOUT:

```bash
perl joomscan.pl -u https://example.com --silent --json > result.json
```

### Example 5: Mass Target Auditing

Scan multiple Joomla targets listed line-by-line in a text file:

```bash
perl joomscan.pl -m targets.txt --threads 5
```

---

## 📊 Command Line Options

| Option | Short | Argument | Description |
|--------|-------|----------|-------------|
| `--url` | `-u` | `<URL>` | Target Joomla URL or domain to audit. |
| `--mass` | `-m` | `<file>` | Batch audit targets listed in a text file. |
| `--enumerate-components` | `-ec` | None | Enumerate installed components via dictionary attack. |
| `--joomla-version` | `-jv` | None | Detect Joomla version and exit immediately. |
| `--threads` | `-t` | `<int>` | Number of concurrent worker threads (default: `5`). |
| `--delay` | None | `<sec>` | Delay between HTTP requests in seconds (e.g. `0.5`). |
| `--cookie` | None | `<str>` | Set HTTP request Cookie header. |
| `--user-agent` | `-a` | `<str>` | Specify custom User-Agent string. |
| `--random-agent` | `-r` | None | Randomize User-Agent for every request. |
| `--proxy` | None | `<URL>` | Route traffic through HTTP, HTTPS, or SOCKS proxy. |
| `--timeout` | None | `<sec>` | HTTP connection timeout in seconds (default: `60`). |
| `--json` | None | None | Output structured JSON scan results to STDOUT. |
| `--silent` | None | None | Suppress banners and non-critical terminal output. |
| `--no-report` | `-nr` | None | Disable generation of report files on disk. |
| `--version` | None | None | Display JoomScan version and exit. |
| `--help` | `-h` | None | Display command-line help screen. |

---

## 🧪 Automated Testing

JoomScan maintains an automated test suite verifying core stability and detection accuracy:

```bash
# Run all tests
prove -I. t/

# Run individual test files with verbose output
perl -I. t/01_semver.t
perl -I. t/02_eol.t
perl -I. t/06_probe_helpers.t
```

Test coverage includes:
- **SemVer logic** (`t/01_semver.t`): Range parsing, version bounds, and edge cases.
- **Lifecycle & EOL** (`t/02_eol.t`): Support states from Joomla 1.0 to Joomla 6.x.
- **CLI parsing** (`t/03_cli.t`): Flag handling and parameter validation.
- **Database integrity** (`t/04_db_integrity.t`): Format checks on vulnerability dictionaries.
- **Worker pool concurrency** (`t/05_pool.t`): Parallel chunking, error handling, and IPC pipes.
- **Probe helpers & verifiers** (`t/06_probe_helpers.t`): Soft-404 baseline contrast, sensitive file signatures, root fallbacks, and Joomla 6.1.3 detection.

---

## 👥 Authors & Community

- **Original Authors & Project Leaders**:
  - Mohammad Reza Espargham ([@rezesp](https://twitter.com/rezesp))
  - Ali Razmjoo ([@Ali_Razmjo0](https://twitter.com/Ali_Razmjo0))
- **Maintainer**:
  - [DragonJAR SAS](https://www.dragonjar.org)
- **Official Resources**:
  - [OWASP Project Page](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project)
  - [GitHub Repository](https://github.com/DragonJAR/joomscan)
  - [Issue Tracker](https://github.com/DragonJAR/joomscan/issues)
  - [YouTube Introduction](https://www.youtube.com/watch?v=Ik2CJ9LkuoI)

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

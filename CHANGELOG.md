OWASP JoomScan 0.0.8 [2026 Refresh]
============
* Core vulnerability database rebuilt with all 221 official JSST advisories
  (2017-2026): version-range matcher (ex. "4.0.0-4.2.7"), CVE / Type / Description /
  Fixed-version / NVD + Security Centre references, up to August 2026 (Joomla 6.1.3)
* Shared engine core/lib.pl (DRY): multi-tier version detection (Tiers 1-6), baseline
  calibration against soft-404 portals, and root domain fallback for subpath targets
* Server baseline calibration (calibrate_target_baseline): eliminates false positives
  on catch-all HTTP 200 responses by fingerprinting non-existent probe title and length
* Syntactic content verification (verify_sensitive_file): requires authentic signatures
  (class JConfig, [core], .env key-pairs, admin login tokens) before confirming leaks
* Modernized offline HTML report dashboard: single-file, responsive, zero external CDNs,
  dynamic 5-dimension security posture scoring, and 24-hour remediation plans
* Concurrency & rate-limiting: worker pool (run_pool) with configurable threads (--threads),
  request delay (--delay), and automatic backoff on HTTP 429/503
* Automated test suite (t/): 89 unit tests across 6 test suites validating SemVer logic,
  lifecycle states, CLI options, db integrity, worker pool, and probe verifiers
* Documentation: bilingual README (English / Spanish) designed to DragonJAR skill standards
* New: passive extension discovery from frontend DOM assets
* New: extension sensitive-endpoint auditor (data-driven, non-destructive probes
  only for detected extensions - Akeeba, RSForm, docman, jckeditor, ...)
* New: Joomla API unauthenticated disclosure detector - CVE-2023-23752
* New: End-of-Life / support status check (Joomla 1.x - 6.x, 2026 matrix)
* New: sensitive files & VCS metadata finder (.env, .git/HEAD, Akeeba backups,
  kickstart.php, installer, logs)
* New: security headers checker with hardening baseline (HSTS, CSP, X-Frame-Options,
  nosniff, Referrer-Policy, Permissions-Policy)
* New: configuration.php hardening flags check (debug, error_reporting, force_ssl,
  session_handler) when a readable copy leaks
* New: SARIF v2.1.0 machine-readable report alongside txt/html
* Improved Joomla version detection for modern releases (4.x/5.x/6.x via
  langmetadata.xml, joomla.asset.json, RSS feed <generator>, meta generator tag)
* Admin finder extended: protection-plugin footprint (jSecure/AdminExile) and
  frontend login check
* Fixed: dirlisting false positives on soft-404 payloads
* Components enumeration rewritten: per-component report, no cross-request text
  bleed, file paths fixed (works from any directory)
* A few enhancements

OWASP JoomScan 0.0.7 [Self Challenge]
============
* com_joomanager exploiter removed
* Added new module: Local File Disclosure vulnerability detector (Supports detection of [com_joomanager,s5_media_player,com_hdflvplayer,com_macgallery,com_cckjseblod,fsave,com_portfolio,com_picsell,captcha,com_rsfiles,com_addproperty,com_aceftp,com_jtagmembersdirectory,com_facegallery,com_docman,mod_dvfoldercontent,com_contushdvideoshare,com_jetext,com_product_modul,wddownload,com_community,com_download-monitor])
* Updated  module: Firewall Detector (supports detection of [CloudFlare, Incapsula, Shieldfy, Mod_Security and 28 other modules ])
* Added exploit for jckeditor
* Updated list of components
* A few enhancements

OWASP JoomScan 0.0.6 [#BHUSA]
============
* Updated vulnerability databases
* Added new module: Firewall Detector (supports detection of [CloudFlare, Incapsula, Shieldfy, Mod_Security])
* Added exploit for com_joomanager
* Updated list of common log paths
* A few enhancements

OWASP JoomScan 0.0.5 [KLOT]
============
* Update components database
* Bug fixed (updating module)
* Allow start from any path
* Update backup finder database
* Update report module
* Update validate target method 
* HTTPS improvements
* Fix issue #11 - Incorrect URL output for HTTPS site
* Fix issue #12 - Components scan output issues
* Fix issue #13 - Check a server is live or not!
* Fix issue #9 - Disable redirectable requests for components finder module
* A few enhancements

OWASP JoomScan 0.0.1 [Reborn]
============
* Initial release

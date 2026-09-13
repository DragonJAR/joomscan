use strict;
use warnings;
use HTTP::Response;
use Test::More tests => 28;

our $mepath = ".";
require "./core/lib.pl";

is(is_soft404("<html><head><title>404 Not Found</title></head></html>", 200), 1, "Title 404 detected as soft-404");
is(is_soft404("<html><body><h1>Page Not Found</h1></body></html>", 200), 1, "H1 Not Found detected as soft-404");
is(is_soft404("Short", 200), 1, "Short body detected as soft-404");
is(is_soft404("", 200), 1, "Empty body detected as soft-404");
is(is_soft404("<html><body><h1>Welcome to Joomla</h1><p>Full article content goes here with plenty of text</p></body></html>", 200), 0, "Real content is not soft-404");
is(is_soft404("Real content", 404), 1, "Non-200 code is soft-404");

my $cfg_leak = '<?php class JConfig { public $dbtype = "mysqli"; public $ftp_pass = "secret123"; public $force_ssl = "2"; }';
is(looks_like_config_leak($cfg_leak), 1, "JConfig leak detected");

my $legacy_cfg = '<?php $mosConfig_secret = "abc"; $mosConfig_dbprefix = "jos_";';
is(looks_like_config_leak($legacy_cfg), 1, "Legacy mosConfig leak detected");

is(looks_like_config_leak("<html><body>Normal HTML page</body></html>"), "", "Normal HTML is not config leak");
is(looks_like_config_leak(undef), "", "Undefined body returns empty");

# Baseline contrast tests
our $baseline_calibrated = 1;
our $baseline_is_catchall = 1;
our $baseline_title = "PROPLAN - Pró-Reitoria de Planejamento";
our $baseline_len = 50000;

my $catchall_page = "<html><head><title>PROPLAN - Pró-Reitoria de Planejamento</title></head><body><h1>PROPLAN Home</h1></body></html>";
is(is_soft404($catchall_page, 200), 1, "Catch-all baseline title match detected as soft-404");

# Reset baseline for unit signature tests
$baseline_calibrated = 0;
$baseline_is_catchall = 0;

# Sensitive files verifiers
my ($v1, $n1) = verify_sensitive_file("configuration.php.save", 200, "<html><body>Portal Home</body></html>");
is($v1, 0, "HTML response for configuration.php.save rejected");

my ($v2, $n2) = verify_sensitive_file("configuration.php.save", 200, $cfg_leak);
is($v2, 1, "Genuine JConfig in configuration.php.save verified");

my ($v3, $n3) = verify_sensitive_file(".git/config", 200, "[core]\n\trepositoryformatversion = 0\n");
is($v3, 1, "Genuine Git config verified");

my ($v4, $n4) = verify_sensitive_file(".git/config", 200, "<html><body>404 / Home</body></html>");
is($v4, 0, "HTML response for .git/config rejected");

my ($v5, $n5) = verify_sensitive_file(".env", 200, "DB_PASSWORD=supersecret\nDB_USER=joomla\n");
is($v5, 1, "Genuine .env key-value secrets verified");

my ($v6, $n6) = verify_sensitive_file(".env", 200, "<html><a href='?action=view'>Link</a></html>");
is($v6, 0, "HTML with equal signs rejected for .env");

my $svn_content = "10\n\ndir\n12345\nsvn://svn.example.org/repo/trunk\nsvn://svn.example.org/repo\n";
my ($v7, $n7) = verify_sensitive_file(".svn/entries", 200, $svn_content);
is($v7, 1, "Genuine SVN entries verified");

my ($v8, $n8) = verify_sensitive_file("administrator/error.log", 200, "2026-09-13 14:00:00 [ERROR] Failed to load module\n");
is($v8, 1, "Genuine log file verified");

my ($v9, $n9) = verify_sensitive_file("kickstart.php", 200, "<html><head><title>Akeeba Kickstart</title></head><body>Akeeba Kickstart Core</body></html>");
is($v9, 1, "Genuine Akeeba Kickstart verified");

my ($v10, $n10) = verify_sensitive_file(".DS_Store", 200, "\x00\x00\x00\x01Bud1" . ("\x00" x 4088));
is($v10, 1, "Genuine .DS_Store verified");

# Admin login verifiers
is(is_admin_login("<html><body>Normal Page Content</body></html>"), 0, "Normal page is not admin login");
is(is_admin_login('<form id="form-login"><input name="username" id="mod-login-username"><input type="password"></form>'), 1, "Joomla admin login form recognized");
is(is_admin_login('<title>Joomla! Administration Login</title><input type="password">'), 1, "Joomla admin login title and password recognized");

# Root URL resolution
is(get_root_url("https://uftm.edu.br/proplan"), "https://uftm.edu.br", "Root URL extracted from subpath");
is(get_root_url("http://example.com:8080/joomla/sub"), "http://example.com:8080", "Root URL extracted with port");
is(get_root_url("https://standalone.org"), "https://standalone.org", "Root URL preserved for bare domain");

# Version Detection unit test
my $fake_xml = '<?xml version="1.0" encoding="UTF-8"?><extension version="3.4" type="file"><name>files_joomla</name><version>3.4.8</version></extension>';
our %resp_cache;
$resp_cache{"https://uftm.edu.br/proplan/"} = HTTP::Response->new(200, "OK", ["Content-Type" => "text/html"], "<html><head><title>Proplan</title></head><body>Home</body></html>");
$resp_cache{"https://uftm.edu.br/proplan/administrator/manifests/files/joomla.xml"} = HTTP::Response->new(404, "Not Found", [], "404 Not Found");
$resp_cache{"https://uftm.edu.br/administrator/manifests/files/joomla.xml"} = HTTP::Response->new(200, "OK", ["Content-Type" => "text/xml"], $fake_xml);
is(detect_joomla_version("https://uftm.edu.br/proplan"), "Joomla 3.4.8", "Detects core version via root manifest fallback");



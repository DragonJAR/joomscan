use strict;
use warnings;
use Test::More tests => 10;

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

# joomscan core lib - shared helpers (single source of truth, DRY)
# Used by: modules/eol.pl, modules/api_disclosure.pl, modules/sensitive_files.pl,
#          modules/security_headers.pl, exploit/verexploit.pl, and many others.
#
# Provides (package-less, do()'ed into main): joomla_version_num(), version_in_range(),
# vers_cmp(), EOL table, HTTP probe helpers, and shared detection helpers.
#
# Load guard: this file is do()'ed from several places; only the first do
# executes the definitions.  `no warnings 'redefine'` silences the redefinition
# warnings that Perl emits at compile-time for named subs inside a conditional
# block (the guard controls runtime execution, not compilation).
no warnings 'redefine';

unless($lib_loaded){
$lib_loaded = 1;

# Extract a bare "X.Y.Z" target version from the detected $ver (or from a raw string).
# Returns "" when no numeric dotted version is present.
sub joomla_version_num {
    my ($raw) = @_;
    return "" unless defined $raw;
    if($raw =~ /([0-9]+(?:\.[0-9]+){1,3})/){
        return $1;
    }
    return "";
}

# EOL / support matrix (endoflife.date/joomla, checked 2026-09-13).
# [series, first, last, active_support_end, security_support_end]
our @eol_series = (
    [1, '1.0.0', '1.5.26',  '2012-04-01', '2013-12-31'],
    [2, '2.5.0', '2.5.28',  '2014-12-31', '2017-04-30'],
    [3, '3.0.0', '3.10.12', '2021-08-17', '2023-08-17'],
    [4, '4.0.0', '4.4.14',  '2024-10-15', '2025-10-14'],
    [5, '5.0.0', '5.4.8',   '2026-10-13', '2027-10-12'],
    [6, '6.0.0', '6.1.3',   '2028-10-17', '2029-10-16'],
);

sub eol_series_for {
    my ($v) = @_;
    my $major = $v =~ /^(\d+)/ ? $1 : 0;
    foreach my $s (@eol_series){
        return $s if $s->[0] == $major;
    }
    return undef;
}

sub jdate_ymd {
    my ($t) = @_;
    my @lt = localtime($t);
    return sprintf("%04d-%02d-%02d", $lt[5]+1900, $lt[4]+1, $lt[3]);
}

# Return one of: "active", "aging", "eol", "" (unknown)
sub jsupport_status {
    my ($v) = @_;
    my $s = eol_series_for($v);
    return "" unless $s;
    my $today = jdate_ymd(time());
    # [3] = active support end, [4] = security support end
    if($today gt $s->[4]){ return "eol"; }
    if($today gt $s->[3]){ return "aging"; }
    return "active";
}

# Version comparisons cached in one place so every module/exploit shares the
# same logic (previously duplicated in compare.pl and inline regex hacks).
our %jver_cache;

sub version_part {
    my ($a) = @_;
    return [ map { /^\d+$/ ? 0+$_ : 0 } split /[.+:~-]/, $a ];
}

sub vers_cmp {
    my ($a, $b) = @_;
    my $key = "$a<=>$b";
    return $jver_cache{$key} if exists $jver_cache{$key};
    my $ra = version_part($a);
    my $rb = version_part($b);
    my $n = @$ra > @$rb ? @$ra : @$rb;
    for(my $i=0;$i<$n;$i++){
        my $pa = $i < @$ra ? $ra->[$i] : 0;
        my $pb = $i < @$rb ? $rb->[$i] : 0;
        if($pa > $pb){ $jver_cache{$key} = 1; return 1; }
        if($pa < $pb){ $jver_cache{$key} = -1; return -1; }
    }
    $jver_cache{$key} = 0;
    return 0;
}

# Test whether version $v falls inside the inclusive range [$lo, $hi].
# Empty lo/hi means unbounded on that side. Returns "1" when in range.
sub version_in_range {
    my ($v, $lo, $hi) = @_;
    return "" unless defined $v && $v =~ /^\d+(\.\d+)*$/;
    return "" if(defined $lo && $lo ne "" && vers_cmp($v, $lo) < 0);
    return "" if(defined $hi && $hi ne "" && vers_cmp($v, $hi) > 0);
    return 1;
}

# ---------------------------------------------------------------------------
# HTTP probing helpers (DRY): classifies responses and caches results per-scan
# to eliminate duplicate fetches across modules.
# ---------------------------------------------------------------------------

our %resp_cache;

# Returns 1 when an HTTP response is a soft-404 (status 200 but body indicates not-found/error)
# or when the body is empty / too short to be a real resource.
sub is_soft404 {
    my ($body, $code) = @_;
    return 1 if !defined $body || $body eq "";
    return 1 if defined $code && $code != 200;
    if($body =~ /<title>[^<]*(?:404|not found|page not found|access denied)[^<]*<\/title>/i){
        return 1;
    }
    if($body =~ /<h[1-2]>[^<]*(?:404|not found|page not found)[^<]*<\/h[1-2]>/i){
        return 1;
    }
    if(length($body) < 20){
        return 1;
    }
    return 0;
}

# Fetch a path off $target and return ($code, $body_as_string).
# Uses %resp_cache so repeated probes of the same URL within a scan cost one
# HTTP request.  GET responses are cached; HEAD responses are not (no body).
sub probe_get {
    my ($path) = @_;
    my $url = "$target/$path";
    unless(exists $resp_cache{$url}){
        my $res = $ua->get($url);
        $resp_cache{$url} = $res;
    }
    my $res = $resp_cache{$url};
    my $body = defined $res ? $res->decoded_content : "";
    $body = "" unless defined $body;
    my $code = defined $res ? $res->code : 0;
    return ($code, $body);
}

# Fetch a path off $target with HEAD using $ua (honoring proxy, SSL, cookies,
# timeouts).  If a GET response for the same URL is already cached, its headers
# are reused (a GET response contains everything a HEAD does).
sub probe_head {
    my ($path) = @_;
    my $url = "$target/$path";
    if(exists $resp_cache{$url}){
        my $res = $resp_cache{$url};
        return (0, "") unless defined $res;
        return ($res->code, $res->header('Content-Type') // "");
    }
    my $res = $ua->head($url);
    return (0, "") unless defined $res;
    return ($res->code, $res->header('Content-Type') // "");
}

# Returns 1 when the path responds with a real (non-soft-404) body.
sub probe_path_ok {
    my ($path) = @_;
    my ($code, $body) = probe_get($path);
    return "" unless $code == 200;
    return "" if is_soft404($body, $code);
    return 1;
}

# HEAD-based file detection: 200 + content-type is not text/html → real file.
# Used by backupfinder and errfinder to avoid downloading large files.
sub probe_head_is_file {
    my ($path) = @_;
    my ($code, $ctype) = probe_head($path);
    return "" unless $code == 200;
    return "" if $ctype =~ m{text/html}i;
    return 1;
}

# Shared signature for detecting a leaked configuration.php body.
# Used by com_lfd.pl and configfinder.pl (DRY — single source of truth).
sub looks_like_config_leak {
    my ($body) = @_;
    return "" unless defined $body;
    return 1 if $body =~ m/\$ftp_pass/i;
    return 1 if $body =~ m/\$dbtype/i;
    return 1 if $body =~ m/force_ssl/i;
    return 1 if $body =~ m/mosConfig_secret/i;
    return 1 if $body =~ m/mosConfig_dbprefix/i;
    return 1 if $body =~ m/JConfig/i;
    return "";
}

} # end load guard ($lib_loaded)


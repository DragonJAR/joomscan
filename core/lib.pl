no warnings 'redefine';
use LWP::UserAgent;

unless($lib_loaded){
$lib_loaded = 1;

sub joomla_version_num {
    my ($raw) = @_;
    return "" unless defined $raw;
    if($raw =~ /([0-9]+(?:\.[0-9]+){1,3})/){
        return $1;
    }
    return "";
}

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

sub jsupport_status {
    my ($v) = @_;
    my $s = eol_series_for($v);
    return "" unless $s;
    my $today = jdate_ymd(time());
    if($today gt $s->[4]){ return "eol"; }
    if($today gt $s->[3]){ return "aging"; }
    return "active";
}

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

sub version_in_range {
    my ($v, $lo, $hi) = @_;
    return "" unless defined $v && $v =~ /^\d+(\.\d+)*$/;
    return "" if(defined $lo && $lo ne "" && vers_cmp($v, $lo) < 0);
    return "" if(defined $hi && $hi ne "" && vers_cmp($v, $hi) > 0);
    return 1;
}

our %resp_cache;
our $baseline_calibrated = 0;
our $baseline_code = 0;
our $baseline_title = "";
our $baseline_len = 0;
our $baseline_is_catchall = 0;
our %component_versions = ();

sub calibrate_target_baseline {
    return if $baseline_calibrated;
    return unless defined $target && $target =~ /^https?:\/\//;
    $baseline_calibrated = 1;

    my $rand_token = "joomscan_baseline_" . int(rand(10000000)) . "_" . time() . ".html";
    my $url = "$target/$rand_token";
    my $res = eval { $ua->get($url) };
    return unless defined $res;

    $baseline_code = $res->code;
    my $body = $res->decoded_content // "";
    $baseline_len = length($body);
    if ($body =~ /<title>\s*([^<]+?)\s*<\/title>/i) {
        $baseline_title = $1;
        $baseline_title =~ s/^\s+|\s+$//g;
    }
    if ($baseline_code == 200) {
        $baseline_is_catchall = 1;
    }
}

sub is_soft404 {
    my ($body, $code) = @_;
    return 1 if !defined $body || $body eq "";
    return 1 if defined $code && $code != 200;

    if ($baseline_calibrated && $baseline_is_catchall) {
        if ($baseline_title ne "" && $body =~ /<title>\s*\Q$baseline_title\E\s*<\/title>/i) {
            return 1;
        }
        if ($baseline_len > 100 && $body =~ /<html[^>]*>/i) {
            my $diff = abs(length($body) - $baseline_len);
            if ($diff < ($baseline_len * 0.04) || $diff < 150) {
                return 1;
            }
        }
    }

    if($body =~ /<title>[^<]*(?:404|not found|page not found|access denied|página não encontrada|acesso negado)[^<]*<\/title>/i){
        return 1;
    }
    if($body =~ /<h[1-2]>[^<]*(?:404|not found|page not found|não encontrada)[^<]*<\/h[1-2]>/i){
        return 1;
    }
    if(length($body) < 20){
        return 1;
    }
    return 0;
}

sub verify_sensitive_file {
    my ($sf, $code, $body) = @_;
    return (0, "") unless defined $code && $code == 200;
    return (0, "") if is_soft404($body, $code);
    $body = "" unless defined $body;

    my $is_html = ($body =~ /^\s*<!DOCTYPE/i or $body =~ /<html[^>]*>/i or $body =~ /<head[^>]*>/i);

    if ($sf =~ /\.git\/config/i) {
        return (0, "") if $is_html;
        if ($body =~ /\[(?:core|remote|branch|repositoryformatversion)\]/i) {
            return (1, " - verified Git repository configuration exposure");
        }
        return (0, "");
    }

    if ($sf =~ /\.git\/HEAD/i) {
        return (0, "") if $is_html;
        if ($body =~ /^(?:ref:\s+refs\/[a-zA-Z0-9_\-\/]+|[0-9a-f]{40})\s*$/m) {
            return (1, " - verified Git HEAD pointer exposure");
        }
        return (0, "");
    }

    if ($sf =~ /\.env/i) {
        return (0, "") if $is_html;
        if ($body =~ /^[A-Z0-9_]{2,}\s*=\s*[^\r\n]+/m) {
            return (1, " - verified environment file (.env) with secrets");
        }
        return (0, "");
    }

    if ($sf =~ /configuration\.php|\.bak|\.swp|\.orig|\.save|\.old/i) {
        return (0, "") if $is_html;
        if (looks_like_config_leak($body)) {
            return (1, " - verified Joomla configuration backup file");
        }
        return (0, "");
    }

    if ($sf =~ /\.svn\/entries/i) {
        return (0, "") if $is_html;
        if ($body =~ /^\s*(?:\d+|<\?xml)/) {
            return (1, " - verified Subversion repository metadata");
        }
        return (0, "");
    }
    if ($sf =~ /\.hg\/hgrc/i) {
        return (0, "") if $is_html;
        if ($body =~ /\[paths\]/i) {
            return (1, " - verified Mercurial repository configuration");
        }
        return (0, "");
    }
    if ($sf =~ /\.DS_Store/i) {
        return (0, "") if $is_html;
        if ($body =~ /^\x00\x00\x00\x01Bud1/ or (length($body) > 0 && length($body) % 4096 == 0)) {
            return (1, " - verified macOS .DS_Store file");
        }
        return (0, "");
    }

    if ($sf =~ /kickstart\.php/i) {
        if ($body =~ /Akeeba Kickstart|AKEEBA_KICKSTART|<title>[^<]*Kickstart/i) {
            return (1, " - verified Akeeba Kickstart extraction tool exposed");
        }
        return (0, "");
    }
    if ($sf =~ /installation\//i) {
        if ($body =~ /Joomla!?\s+Installation|view=installation|class="[^"]*install/i) {
            return (1, " - verified Joomla installation directory is accessible");
        }
        return (0, "");
    }

    if ($sf =~ /\.log$/i) {
        return (0, "") if $is_html;
        if ($body =~ /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\b(?:INFO|DEBUG|ERROR|WARNING|NOTICE)\b/) {
            return (1, " - verified log file exposure");
        }
        return (0, "");
    }
    if ($sf =~ /akeeba/i) {
        if ($body =~ /<title>Index of/i or ($body !~ /<html/i && length($body) > 100)) {
            return (1, " - verified Akeeba backup artifact exposed");
        }
        return (0, "");
    }

    if ($sf =~ /\/$/) {
        if ($body =~ /<title>Index of/i or $body =~ /Last modified<\/a>/i or $body =~ /Parent Directory<\/a>/i) {
            return (1, " - directory listing is enabled");
        }
        return (0, "");
    }

    return (0, "");
}

sub is_admin_login {
    my ($body) = @_;
    return 0 unless defined $body;
    return 1 if $body =~ /mod-login-username|id="form-login"|name="username"[^>]*id="mod-login|Joomla!\s+Administration|task=login/i;
    return 1 if $body =~ /<title>[^<]*(?:Joomla!|Administration|Admin Login)[^<]*<\/title>/i && $body =~ /type="password"/i;
    return 0;
}

sub get_root_url {
    my ($u) = @_;
    $u //= $target // "";
    if ($u =~ /^(https?:\/\/[^\/]+)/i) {
        return $1;
    }
    return $u;
}

sub probe_get {
    my ($path) = @_;
    my $url;
    if ($path =~ /^https?:\/\//i) {
        $url = $path;
    } else {
        calibrate_target_baseline() if (!$baseline_calibrated && defined $target && $target =~ /^https?:\/\// && $path !~ /^joomscan_baseline_/);
        $url = "$target/$path";
    }
    unless(exists $resp_cache{$url}){
        our $ua;
        $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 }) unless defined $ua;
        if(defined $delay && $delay > 0){
            select(undef, undef, undef, 0 + $delay);
        }
        my $res = eval { $ua->get($url) };
        if(defined $res && ($res->code == 429 || $res->code == 503)){
            my $retry = $res->header('Retry-After');
            my $wait_time = (defined $retry && $retry =~ /^\d+$/ && $retry <= 10) ? $retry : 1.5;
            select(undef, undef, undef, 0 + $wait_time);
            $res = $ua->get($url);
        }
        $resp_cache{$url} = $res;
    }
    my $res = $resp_cache{$url};
    my $body = defined $res ? $res->decoded_content : "";
    $body = "" unless defined $body;
    my $code = defined $res ? $res->code : 0;
    return ($code, $body);
}

sub probe_url_with_root_fallback {
    my ($path) = @_;
    my ($code, $body) = probe_get($path);
    if ($code == 200 && !is_soft404($body, $code)) {
        return ($code, $body);
    }
    my $root = get_root_url($target);
    if ($root ne "" && $root ne $target && "$root/" ne $target) {
        my $root_url = "$root/$path";
        my ($rcode, $rbody) = probe_get($root_url);
        if ($rcode == 200 && !is_soft404($rbody, $rcode)) {
            return ($rcode, $rbody);
        }
    }
    return ($code, $body);
}

sub detect_joomla_version {
    my ($target_url) = @_;
    $target_url //= $target // "";
    local $target = $target_url if defined $target_url && $target_url ne "";

    # 1. Homepage Headers & Meta
    my ($hcode, $hbody) = probe_get("");
    my $hres = $resp_cache{"$target/"} // $resp_cache{$target};
    if (defined $hres) {
        my $gen_hdr = $hres->header('X-Meta-Generator') // "";
        if ($gen_hdr =~ /([0-9]+(?:\.[0-9]+)+)/) {
            return "Joomla $1";
        }
    }
    if ($hbody =~ /<meta[^>]*name=["']generator["'][^>]*content=["']Joomla!\s*([0-9]+(?:\.[0-9]+)+)/i) {
        return "Joomla $1";
    }

    # 2. XML Manifests with root domain fallback
    # Primary: Core files manifest (definitive core version)
    my @core_manifests = (
        'administrator/manifests/files/joomla.xml',
    );
    foreach my $manifest (@core_manifests) {
        my ($code, $body) = probe_url_with_root_fallback($manifest);
        next if $code != 200 || is_soft404($body, $code);
        next unless ($body =~ /<\?xml|<extension/i);
        if ($body =~ /<version>\s*([0-9]+(?:\.[0-9]+)+)\s*<\/version>/i) {
            return "Joomla $1";
        }
    }

    # Secondary: Language manifests & component manifests
    my @sec_manifests = (
        'language/en-GB/en-GB.xml',
        'language/en-GB/langmetadata.xml',
        'administrator/components/com_content/content.xml',
        'administrator/components/com_plugins/plugins.xml',
        'administrator/components/com_media/media.xml',
        'mambots/content/moscode.xml',
    );

    # Detect language tag from HTML to check native language packs (e.g. pt-BR, es-ES)
    if ($hbody =~ /<html[^>]*lang=["']([a-zA-Z]{2}(?:-[a-zA-Z]{2})?)["']/i) {
        my $lang_tag = $1;
        my ($l1, $l2) = split /-/, $lang_tag;
        my $canonical = lc($l1) . (defined $l2 ? "-" . uc($l2) : "");
        unshift @sec_manifests, "language/$canonical/$canonical.xml", "language/$canonical/langmetadata.xml";
    }

    foreach my $manifest (@sec_manifests) {
        my ($code, $body) = probe_url_with_root_fallback($manifest);
        next if $code != 200 || is_soft404($body, $code);
        next unless ($body =~ /<\?xml|<extension|<metafile|<version>/i);
        if ($body =~ /<version>\s*([0-9]+(?:\.[0-9]+)+)\s*<\/version>/i or $body =~ /<version\s+[^>]*>([0-9]+(?:\.[0-9]+)+)<\/version>/i) {
            return "Joomla $1";
        }
    }

    # 3. Modern Joomla 4, 5 & 6 Asset Manifests
    my ($aj_code, $aj_body) = probe_url_with_root_fallback('media/system/joomla.asset.json');
    if ($aj_code == 200 && !is_soft404($aj_body, $aj_code)) {
        if ($aj_body =~ /"version"\s*:\s*"([0-9]+(?:\.[0-9]+)+)"/i) {
            return "Joomla $1";
        }
    }

    # 4. RSS / Feeds
    my @feeds = (
        'index.php?format=feed&type=rss',
        'index.php?option=com_content&view=featured&format=feed',
        'index.php?option=com_content&view=category&layout=blog&format=feed',
    );
    foreach my $feed (@feeds) {
        my ($code, $body) = probe_url_with_root_fallback($feed);
        next if $code != 200 || is_soft404($body, $code);
        if ($body =~ /<generator>Joomla!\s*([0-9]+(?:\.[0-9]+)+)/i) {
            return "Joomla $1";
        }
    }

    # 5. Core Documentation / Config Hints
    my ($r_code, $r_body) = probe_url_with_root_fallback('README.txt');
    if ($r_code == 200 && !is_soft404($r_body, $r_code)) {
        if ($r_body =~ /package to version\s+([0-9]+(?:\.[0-9]+)+)/i) {
            return "Joomla $1";
        }
    }

    # 6. Core Asset Signatures (Heuristic Fingerprinting for hardened/restricted environments)
    my ($jq_code, $jq_body) = probe_url_with_root_fallback('media/jui/js/jquery.min.js');
    if ($jq_code == 200 && !is_soft404($jq_body, $jq_code)) {
        if ($jq_body =~ /jQuery\s+v([0-9]+(?:\.[0-9]+)+)/i) {
            my $jqv = $1;
            if ($jqv =~ /^1\.11\./) {
                return "Joomla 3.4 - 3.6 (inferred from JUI jQuery $jqv)";
            } elsif ($jqv =~ /^1\.12\./) {
                return "Joomla 3.7 - 3.9 (inferred from JUI jQuery $jqv)";
            } elsif ($jqv =~ /^3\.5\./) {
                return "Joomla 3.9.21 - 3.10 (inferred from JUI jQuery $jqv)";
            } elsif ($jqv =~ /^1\.10\./) {
                return "Joomla 3.2 - 3.3 (inferred from JUI jQuery $jqv)";
            } elsif ($jqv =~ /^1\.8\./) {
                return "Joomla 3.0 - 3.1 (inferred from JUI jQuery $jqv)";
            }
        }
    }

    my ($sys_code, $sys_body) = probe_url_with_root_fallback('templates/system/css/system.css');
    if ($sys_code == 200 && !is_soft404($sys_body, $sys_code)) {
        if ($sys_body =~ /20196 2011-01-09/) { return "Joomla 1.6"; }
        elsif ($sys_body =~ /21322 2011-05-11/) { return "Joomla 1.7"; }
        elsif ($sys_body =~ /system\.css 2005/) { return "Joomla 1.5"; }
    }

    return "";
}

sub probe_head {
    my ($path) = @_;
    my $url = "$target/$path";
    if(exists $resp_cache{$url}){
        my $res = $resp_cache{$url};
        return (0, "") unless defined $res;
        return ($res->code, $res->header('Content-Type') // "");
    }
    if(defined $delay && $delay > 0){
        select(undef, undef, undef, 0 + $delay);
    }
    my $res = $ua->head($url);
    if(defined $res && ($res->code == 429 || $res->code == 503)){
        my $retry = $res->header('Retry-After');
        my $wait_time = (defined $retry && $retry =~ /^\d+$/ && $retry <= 10) ? $retry : 1.5;
        select(undef, undef, undef, 0 + $wait_time);
        $res = $ua->head($url);
    }
    return (0, "") unless defined $res;
    return ($res->code, $res->header('Content-Type') // "");
}

sub probe_path_ok {
    my ($path) = @_;
    my ($code, $body) = probe_get($path);
    return "" unless $code == 200;
    return "" if is_soft404($body, $code);
    return 1;
}

sub probe_head_is_file {
    my ($path) = @_;
    my ($code, $ctype) = probe_head($path);
    return "" unless $code == 200;
    return "" if $ctype =~ m{text/html}i;
    return 1;
}

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

# --- Shared declarative baseline-header table (single source of truth: modules/security_headers.pl + modules/validation.pl) ---
our %SECURITY_HEADERS = (
    'Strict-Transport-Security' => {
        desc    => 'HSTS',
        pattern => qr/max-age=\s*\d{6,}/i,
        okay    => "HSTS with max-age >= 1 week recommended (e.g. max-age=31536000; includeSubDomains; preload)",
    },
    'Content-Security-Policy'   => {
        desc    => 'CSP',
        pattern => qr/(default-src|script-src|object-src)/i,
        okay    => "CSP with default-src 'self' recommended",
    },
    'X-Frame-Options'           => {
        desc    => 'anti-clickjacking',
        pattern => qr/(SAMEORIGIN|DENY)/i,
        okay    => "X-Frame-Options: SAMEORIGIN or DENY recommended",
    },
    'X-Content-Type-Options'    => {
        desc    => 'MIME-sniffing protection',
        pattern => qr/nosniff/i,
        okay    => "X-Content-Type-Options: nosniff recommended",
    },
    'Referrer-Policy'           => {
        desc    => 'referrer leakage control',
        pattern => qr/(strict-origin-when-cross-origin|no-referrer|same-origin)/i,
        okay    => "Referrer-Policy: strict-origin-when-cross-origin recommended",
    },
    'Permissions-Policy'        => {
        desc    => 'browser feature restriction',
        pattern => qr/(camera|microphone|geolocation)/i,
        okay    => "Permissions-Policy restricting camera/microphone/geolocation recommended",
    },
);

# --- Deterministic validation helpers (pure functions over one HTTP response; unit-tested in t/07_validation.t) ---

# validate_headers($res): verdict per baseline header. status: compliant | weak | missing
sub validate_headers {
    my ($res) = @_;
    my @out;
    for my $h (sort keys %SECURITY_HEADERS) {
        my $v = defined $res ? $res->header($h) : undef;
        $v = "" unless defined $v;
        my $status = "missing";
        if ($v ne "") {
            $status = ($v =~ $SECURITY_HEADERS{$h}{pattern}) ? "compliant" : "weak";
        }
        push @out, { header => $h, value => $v, status => $status };
    }
    return \@out;
}

# validate_isolation_headers($res): verdict shape for cross-origin isolation headers
# (COOP/COEP/CORP). All missing on an HTTPS page embedding third-party content = weak isolation (WSTG 4.2.4).
sub validate_isolation_headers {
    my ($res) = @_;
    my @spec = (
        ['Cross-Origin-Opener-Policy',   'same-origin',                  'COOP'],
        ['Cross-Origin-Embedder-Policy', 'require-corp|credentialless',  'COEP'],
        ['Cross-Origin-Resource-Policy', 'same-origin|same-site',        'CORP'],
    );
    my @out;
    for my $e (@spec) {
        my ($h, $pat, $short) = @$e;
        my $v = defined $res ? $res->header($h) : undef;
        $v = "" unless defined $v;
        my $status = "missing";
        if ($v ne "") {
            $status = ($v =~ /$pat/i) ? "compliant" : "weak";
        }
        push @out, { header => $h, short => $short, value => $v, status => $status };
    }
    return \@out;
}

# validate_mixed_content($body, $scheme): sorted unique http:// asset URLs loaded from an
# HTTPS page (src/href/action attributes). Namespace and feed references are excluded.
sub validate_mixed_content {
    my ($body, $scheme) = @_;
    return [] if !defined $body || $body eq "";
    return [] if defined $scheme && $scheme ne "" && $scheme ne "https";
    my %seen;
    my $base = get_root_url($target) . "/";
    while ($body =~ /<\w+\b[^>]*?\b(?:src|href|action)\s*=\s*["'](http:\/\/[^"'\s>]+)["']/gi) {
        my $u = $1;
        next if $u =~ /\.(?:xml|rss|dtd)\b/i;
        next if $u =~ /(?:w3\.org|xmlns|opensearchdescription)/i;
        $u = $base . $u if $u =~ m#^/#;
        $seen{$u} = 1;
    }
    return [sort keys %seen];
}

# validate_sri($body): sorted unique external script/stylesheet URLs lacking an integrity
# attribute (CWE-353). Same-origin, root-relative, data: and inline URLs are not reported.
sub validate_sri {
    my ($body) = @_;
    return [] if !defined $body || $body eq "";
    my $base = get_root_url($target);
    my %seen;
    while ($body =~ /<(\w+)\b([^>]*)>/gi) {
        my ($tag, $attrs) = ($1, $2);
        next unless $tag =~ /^(?:script|link)$/i;
        next if $attrs =~ /\bintegrity\s*=/i;
        my $url;
        if ($tag =~ /^script$/i) {
            ($url) = $attrs =~ /\bsrc\s*=\s*["']([^"']+)["']/i;
        } else {
            my ($rel) = $attrs =~ /\brel\s*=\s*["']([^"']*)["']/i;
            if (defined $rel && $rel =~ /stylesheet/i) {
                ($url) = $attrs =~ /\bhref\s*=\s*["']([^"']+)["']/i;
            }
        }
        next unless defined $url;
        next if $url =~ m#^(?:/|\.|\#|data:|javascript:)#i;
        next if defined $base && $base ne "" && $url =~ /^\Q$base\E/i;
        next unless $url =~ m#^(?:https?:)?//#i;
        $seen{$url} = 1;
    }
    return [sort keys %seen];
}

# --- Joomla-specific oracles (pure classifiers over HTTP responses; unit-tested in t/07_validation.t) ---

# extract_templates($body): sorted unique template directory names from asset URLs
# (/templates/<name>/...). Template names are filesystem tokens ([A-Za-z0-9_-]+).
sub extract_templates {
    my ($body) = @_;
    return [] if !defined $body || $body eq "";
    my %seen;
    while ($body =~ m#/templates/([A-Za-z0-9_\-]+)/#gi) { $seen{lc $1} = 1; }
    return [sort keys %seen];
}

# parse_template_manifest($body): <version> from a templateDetails.xml manifest.
# Requires the template-install signature so arbitrary XML cannot fake it.
sub parse_template_manifest {
    my ($body) = @_;
    return "" if !defined $body || $body eq "";
    return "" unless $body =~ /template-install\.dtd|type="template"/i;
    my ($v) = $body =~ m#<version>([^<]+)</version>#i;
    $v = "" unless defined $v;
    $v =~ s/^\s+|\s+$//g;
    return $v;
}

# parse_composer_inventory($body): "name version" pairs from composer installed.json.
sub parse_composer_inventory {
    my ($body) = @_;
    return [] if !defined $body || $body eq "";
    return [] unless $body =~ /^\s*[\[{]/;
    my @out;
    while ($body =~ /"name"\s*:\s*"([^"]+)"\s*,\s*"version"\s*:\s*"([^"]+)"/gi) {
        push @out, "$1 $2";
    }
    return \@out;
}

# has_modline_disclosure($body): Joomla only emits module-position markers (the
# "modline" wrapper) when the page was rendered with the ?tp=1 debug parameter.
sub has_modline_disclosure {
    my ($body) = @_;
    return 0 if !defined $body || $body eq "";
    return ($body =~ /modline/i) ? 1 : 0;
}

# looks_like_contenthistory($body): markers of a contenthistory view/JSON payload
# served without authentication. Login walls and catch-all templates never contain them.
sub looks_like_contenthistory {
    my ($body) = @_;
    return 0 if !defined $body || $body eq "";
    return ($body =~ /versionsList|loadhistory|history\.(?:add|keep)|"success"\s*:\s*true\s*,\s*"data"/i) ? 1 : 0;
}

# validate_session_headers($res): Joomla state headers that leak session posture to
# shared caches/CDNs (X-Logged-In). status: disclosed | absent.
sub validate_session_headers {
    my ($res) = @_;
    my @out;
    for my $h ('X-Logged-In') {
        my $v = defined $res ? $res->header($h) : undef;
        push @out, { header => $h, value => (defined $v ? $v : ""), status => (defined $v && $v ne "") ? "disclosed" : "absent" };
    }
    return \@out;
}

# --- Structured finding ledger (single source of truth for reports; modules append via record_finding, report.pl serializes) ---
our @FINDINGS;

sub record_finding {
    my %f = (
        id => "", title => "", state => "LIKELY", severity => "INFO",
        cwe => "", owasp => "", evidence => "", remediation => "", @_
    );
    $f{target} = $target // "";
    $f{id} = sprintf("JOOM-%03d", scalar(@FINDINGS) + 1) if $f{id} eq "";
    push @FINDINGS, \%f;
    return $f{id};
}

sub findings_snapshot {
    my ($mode) = @_;
    my @snap = map { { %{$_} } } @FINDINGS;
    return \@snap unless defined $mode && $mode eq "json";
    # canonical(1): key-sorted, character semantics (safe for a :encoding(UTF-8) handle;
    # encode_json would die on wide chars in evidence).
    my $json = eval { require JSON::PP; JSON::PP->new->canonical(1)->encode(\@snap) };
    return $json if defined $json;
    my $esc = sub { my $s = $_[0] // ""; $s =~ s/\\/\\\\/g; $s =~ s/"/\\"/g; $s =~ s/[\r\n]+/ /g; $s =~ s/([\x00-\x1f])/sprintf "\\u%04x", ord $1/ge; '"' . $s . '"'; };
    my @parts = map {
        "{" . join(",", map { $esc->($_) . ":" . $esc->($_->{$_}) } sort keys %$_) . "}"
    } @snap;
    return "[" . join(",", @parts) . "]";
}

sub run_pool {
    my ($items, $worker_fn, $workers) = @_;
    $workers = $threads if (!defined $workers || $workers <= 0);
    $workers = 5 unless defined $workers && $workers > 0;
    return [] unless defined $items && @$items;
    $workers = @$items if @$items < $workers;

    if ($workers <= 1 || $^O eq 'MSWin32') {
        my @res;
        for my $item (@$items) {
            my $r = $worker_fn->($item);
            push @res, $r if defined $r;
        }
        return \@res;
    }

    pipe(my $reader, my $writer) or die "pipe: $!";
    my $chunk_size = int((@$items + $workers - 1) / $workers);
    my @pids;

    for (my $w = 0; $w < $workers; $w++) {
        my $start = $w * $chunk_size;
        last if $start >= @$items;
        my $end = $start + $chunk_size - 1;
        $end = $#$items if $end > $#$items;
        my @chunk = @$items[$start .. $end];

        my $pid = fork();
        unless (defined $pid) {
            for my $item (@chunk) {
                my $r = $worker_fn->($item);
                print $writer "$r\n" if defined $r;
            }
            next;
        }
        if ($pid == 0) {
            close $reader;
            for my $item (@chunk) {
                my $r = $worker_fn->($item);
                print $writer "$r\n" if defined $r;
            }
            close $writer;
            exit 0;
        }
        push @pids, $pid;
    }
    close $writer;
    my @results;
    while (my $line = <$reader>) {
        chomp $line;
        push @results, $line if $line ne "";
    }
    close $reader;
    waitpid($_, 0) for @pids;
    return \@results;
}

}

1;

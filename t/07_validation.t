use strict;
use warnings;
use Test::More tests => 37;

our $mepath = ".";
require "./core/lib.pl";

# --- extract_templates: template directory names from asset URLs ---
is_deeply(
    extract_templates('<link href="/templates/protostar/js/app.js"><a href="/templates/beez3/css.css">'),
    ['beez3', 'protostar'],
    "extract_templates returns sorted unique names"
);
is_deeply(
    extract_templates('<img src="/templates/Protostar/x.png"><img src="/templates/protostar/y.png">'),
    ['protostar'],
    "extract_templates is case-insensitive and deduplicates"
);
is_deeply(extract_templates(undef), [], "extract_templates(undef) returns empty list");
is_deeply(extract_templates(""), [], "extract_templates('') returns empty list");

# --- parse_template_manifest: version only behind the template-install signature ---
is(
    parse_template_manifest('<?xml version="1.0"?><!DOCTYPE extension PUBLIC "template-install.dtd"><extension><version>3.0.3</version></extension>'),
    "3.0.3",
    "parse_template_manifest reads version behind DTD signature"
);
is(
    parse_template_manifest('<extension type="template" client="site"><name>x</name><version>1.2.0</version></extension>'),
    "1.2.0",
    "parse_template_manifest accepts type=template signature"
);
is(
    parse_template_manifest('<?xml version="1.0"?><config><version>9.9.9</version></config>'),
    "",
    "parse_template_manifest rejects XML without the template signature"
);
is(
    parse_template_manifest('<extension type="template"><name>no-version</name></extension>'),
    "",
    "parse_template_manifest returns empty when version tag absent"
);

# --- parse_composer_inventory: composer installed.json dependency pairs ---
is_deeply(
    parse_composer_inventory('[{"name": "symfony/polyfill", "version": "1.28.0"}, {"name": "joomla/uri", "version": "2.0.1"}]'),
    ["symfony/polyfill 1.28.0", "joomla/uri 2.0.1"],
    "parse_composer_inventory extracts name/version pairs from array JSON"
);
is_deeply(
    parse_composer_inventory('{"packages": [{"name": "a/b", "version": "1.0.0"}], "dev": true}'),
    ["a/b 1.0.0"],
    "parse_composer_inventory extracts from installed.json v2 object shape"
);
is_deeply(parse_composer_inventory("<html>404</html>"), [], "parse_composer_inventory rejects non-JSON bodies");

# --- has_modline_disclosure: ?tp=1 module-position markers ---
is(has_modline_disclosure('<div class="modline-3" style="outline:1px solid">banner</div>'), 1, "modline marker detected");
is(has_modline_disclosure("<html>normal rendered page</html>"), 0, "no modline markers on a normal page");
is(has_modline_disclosure(undef), 0, "has_modline_disclosure(undef) is 0");

# --- looks_like_contenthistory: unauthenticated history view/JSON markers ---
is(looks_like_contenthistory('{"success":true,"data":[{"versionsList":[]}]}'), 1, "contenthistory JSON payload detected");
is(looks_like_contenthistory('<form action="/administrator/index.php"><input name="username"></form>'), 0, "login wall is not contenthistory");

# --- validate_session_headers: X-Logged-In posture over HTTP::Response ---
{
    my $r = HTTP::Response->new(200);
    $r->header('X-Logged-In' => 'true');
    my ($disc) = grep { $_->{status} eq "disclosed" } @{ validate_session_headers($r) };
    ok(defined $disc && $disc->{value} eq "true", "X-Logged-In present is reported as disclosed");

    my $empty = HTTP::Response->new(200);
    my ($absent) = grep { $_->{status} eq "absent" } @{ validate_session_headers($empty) };
    ok(defined $absent, "missing X-Logged-In is reported as absent");
}

# --- findings_snapshot: deterministic JSON ledger ---
{
    our @FINDINGS;
    @FINDINGS = ();
    my $id = record_finding(
        title       => "Unit-test finding",
        state       => "CONFIRMED",
        severity    => "LOW",
        evidence    => "evidencia con acentos y \"comillas\"",
        remediation => "fix it",
    );
    is($id, "JOOM-001", "record_finding assigns sequential JOOM id");
    my $json = findings_snapshot("json");
    my $decoded = eval { require JSON::PP; JSON::PP->new->decode($json) };
    ok(defined $decoded && ref($decoded) eq "ARRAY" && @$decoded == 1, "findings_snapshot(json) round-trips");
    is($decoded->[0]{id}, "JOOM-001", "ledger entry carries its id");
    is($decoded->[0]{evidence}, "evidencia con acentos y \"comillas\"", "ledger evidence survives encoding intact");
    @FINDINGS = ();
}

# --- corevul.txt regression: Joomla 3.4.8 coverage (live-validated false negative) ---
# The production matcher in exploit/verexploit.pl: exact-version tokens, operator
# tokens (<=, >=, <, >, ==) and closed ranges (lo-hi). Count advisories that hit 3.4.8.
{
    open(my $cvfh, "<:encoding(UTF-8)", "exploit/db/corevul.txt") or die $!;
    my $hits = 0;
    my %cve_rows;
    while (my $row = <$cvfh>) {
        chomp $row;
        next if $row =~ /^\s*$/;
        my ($verfield, $descf) = split /\|/, $row, 2;
        next unless defined $descf;
        if ($descf =~ /CVE-(\d{4}-\d+)/) { $cve_rows{"CVE-$1"} = $verfield // ""; }
        my $match = 0;
        foreach my $rng (split /,/, ($verfield // "")) {
            $rng =~ s/^\s+|\s+$//g;
            next if $rng eq "";
            if ($rng =~ /^(<=|>=|<|>|==)\s*([0-9]+(?:\.[0-9]+)*)$/) {
                my $c = vers_cmp("3.4.8", $2);
                $match = 1 if ($1 eq "<" && $c < 0) || ($1 eq "<=" && $c <= 0)
                           || ($1 eq ">" && $c > 0) || ($1 eq ">=" && $c >= 0)
                           || ($1 eq "==" && $c == 0);
            } elsif ($rng =~ /^([0-9]+(?:\.[0-9]+)*)\s*-\s*([0-9]+(?:\.[0-9]+)*)$/) {
                $match = 1 if version_in_range("3.4.8", $1, $2);
            } elsif ($rng =~ /^([0-9]+(?:\.[0-9]+)*)$/) {
                $match = 1 if vers_cmp("3.4.8", $rng) == 0;
            }
            last if $match;
        }
        $hits++ if $match;
    }
    close $cvfh;
    cmp_ok($hits, ">=", 5, "Joomla 3.4.8 matches at least 5 core advisories (regression for the live-validated FN)");
    ok(($cve_rows{"CVE-2016-9836"} // "") =~ /3\.4\.8/, "CVE-2016-9836 (shell upload) covers 3.4.8");
    ok(($cve_rows{"CVE-2016-8870"} // "") =~ /3\.4\.8/, "CVE-2016-8870 (account creation) covers 3.4.8");
}

# --- header/body oracles (checks 1-4): validate_headers, validate_isolation_headers, validate_mixed_content, validate_sri ---
{
    my $r = HTTP::Response->new(200);
    $r->header('Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload');
    $r->header('X-Content-Type-Options' => 'nosniff');
    $r->header('Referrer-Policy' => 'no-referrer');
    $r->header('X-Frame-Options' => 'DENY');
    $r->header('Content-Security-Policy' => "default-src 'self'");
    $r->header('Permissions-Policy' => 'geolocation=()');
    my @hv = @{ validate_headers($r) };
    is(scalar(grep { $_->{status} eq "compliant" } @hv), 6, "validate_headers marks all six present-compliant headers");
    my ($hsts) = grep { $_->{header} eq 'Strict-Transport-Security' } @hv;
    is($hsts->{status}, "compliant", "HSTS long max-age is compliant");

    my $weak = HTTP::Response->new(200);
    $weak->header('Strict-Transport-Security' => 'max-age=60');
    $weak->header('X-Content-Type-Options' => 'nosniff');
    my ($wh) = grep { $_->{header} eq 'Strict-Transport-Security' } @{ validate_headers($weak) };
    is($wh->{status}, "weak", "short HSTS max-age is weak");

    my $empty = HTTP::Response->new(200);
    my ($mh) = grep { $_->{status} eq "missing" } @{ validate_headers($empty) };
    is(scalar(grep { $_->{status} eq "missing" } @{ validate_headers($empty) }), 6, "no headers => all missing");
    is_deeply(validate_headers(undef), validate_headers($empty), "validate_headers(undef) treats as missing");

    my @iso = @{ validate_isolation_headers($r) };
    is(scalar(grep { $_->{status} eq "missing" } @iso), 3, "COOP/COEP/CORP all missing when absent");
    my $iso_ok = HTTP::Response->new(200);
    $iso_ok->header('Cross-Origin-Opener-Policy' => 'same-origin');
    $iso_ok->header('Cross-Origin-Embedder-Policy' => 'credentialless');
    $iso_ok->header('Cross-Origin-Resource-Policy' => 'same-site');
    is(scalar(grep { $_->{status} eq "compliant" } @{ validate_isolation_headers($iso_ok) }), 3, "isolation headers compliant when set");

    is_deeply(validate_mixed_content('<img src="http://cdn.example.com/a.png"><link href="http://other.example/b.css">', "https"), ["http://cdn.example.com/a.png", "http://other.example/b.css"], "mixed content lists sorted unique http:// assets");
    is_deeply(validate_mixed_content('<img src="http://w3.org/ns/x.png">', "https"), [], "mixed content excludes namespace/reference URLs");
    is_deeply(validate_mixed_content("<img src='/img/x.png'>", "https"), [], "mixed content ignores root-relative URLs");
    is_deeply(validate_mixed_content('<img src="http://x.example/a.png">', "http"), [], "mixed content only evaluated on https pages");

    my $sri_html = '<script src="https://cdn.example.com/app.js"></script><link rel="stylesheet" href="https://cdn.example.com/s.css"><script src="/local.js"></script><script src="https://ok.example.com/ok.js" integrity="sha384-abc"></script>';
    is_deeply(validate_sri($sri_html), ["https://cdn.example.com/app.js", "https://cdn.example.com/s.css"], "validate_sri lists external assets lacking integrity, skips local/integrity-having");
}

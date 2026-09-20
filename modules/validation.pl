dprint("Running deterministic validation layer");

do "$mepath/core/lib.pl";

# Deterministic, reusable validation pass over the already-fetched homepage
# (probe_get is response-cached, so this module issues no extra HTTP requests).
# Pure classifiers live in core/lib.pl and are unit-tested in t/07_validation.t.

my ($hcode, $vbody) = probe_get("");
my $hres = $resp_cache{"$target/"} // $resp_cache{$target};
my ($vscheme) = ($target // "") =~ /^(https?):/i;
$vscheme = "http" unless defined $vscheme;

# 1. Baseline security headers (shared %SECURITY_HEADERS table)
my $verdicts = validate_headers($hres);
my @missing = grep { $_->{status} eq "missing" } @$verdicts;
my @weak    = grep { $_->{status} eq "weak" }    @$verdicts;
if (@missing) {
    record_finding(
        title       => "Missing baseline security headers",
        state       => "CONFIRMED",
        severity    => "MEDIUM",
        cwe         => "CWE-693",
        owasp       => "A05:2021",
        evidence    => join(", ", map { $_->{header} } @missing),
        remediation => "Add the missing headers in the web server or .htaccess config (per-header guidance in the security headers section).",
    );
} elsif (@weak) {
    record_finding(
        title       => "Weak security header values",
        state       => "CONFIRMED",
        severity    => "LOW",
        cwe         => "CWE-693",
        owasp       => "A05:2021",
        evidence    => join("; ", map { "$_->{header} => $_->{value}" } @weak),
        remediation => "Strengthen the listed headers to the recommended values from the shared header table.",
    );
}

# 2. Cross-origin isolation headers (COOP/COEP/CORP)
my $iso = validate_isolation_headers($hres);
my @iso_bad = grep { $_->{status} ne "compliant" } @$iso;
if (@iso_bad && $vscheme eq "https") {
    record_finding(
        title       => "No cross-origin isolation headers (COOP/COEP/CORP)",
        state       => "CONFIRMED",
        severity    => "LOW",
        cwe         => "CWE-693",
        owasp       => "A05:2021",
        evidence    => join(", ", map { $_->{header} . ": " . ($_->{status} eq "weak" ? $_->{value} : "missing") } @iso_bad),
        remediation => "Set Cross-Origin-Opener-Policy: same-origin, Cross-Origin-Embedder-Policy: require-corp and Cross-Origin-Resource-Policy: same-origin.",
    );
}

# 3. Mixed content: HTTP assets referenced from an HTTPS page
my $mixed = validate_mixed_content($vbody, $vscheme);
if (@$mixed) {
    record_finding(
        title       => "Mixed content: HTTP assets loaded on HTTPS page",
        state       => "CONFIRMED",
        severity    => "MEDIUM",
        cwe         => "CWE-311",
        owasp       => "A02:2021",
        evidence    => join("\n", @$mixed),
        remediation => "Serve every referenced asset over HTTPS; update template overrides and third-party widgets to https:// URLs.",
    );
}

# 4. External scripts/styles without Subresource Integrity
my $sri = validate_sri($vbody);
if (@$sri) {
    record_finding(
        title       => "External scripts/styles without Subresource Integrity (SRI)",
        state       => "CONFIRMED",
        severity    => "LOW",
        cwe         => "CWE-353",
        owasp       => "A08:2021",
        evidence    => join("\n", @$sri),
        remediation => "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to third-party <script>/<link rel=stylesheet> tags.",
    );
}

# 5. Version disclosure via publicly readable core manifests (cache-reused probes)
my @manifest_checks = (
    'administrator/manifests/files/joomla.xml',
    'language/en-GB/en-GB.xml',
    'language/en-GB/langmetadata.xml',
    'README.txt',
);
my @exposed_manifests;
foreach my $manifest (@manifest_checks) {
    my ($mcode, $mbody) = probe_url_with_root_fallback($manifest);
    next if !defined $mcode || $mcode != 200 || is_soft404($mbody, $mcode);
    next unless $mbody =~ /<version>|<extension|package to version/i;
    push @exposed_manifests, $manifest;
}
if (@exposed_manifests) {
    record_finding(
        title       => "Joomla version disclosure via readable core manifests",
        state       => "CONFIRMED",
        severity    => "LOW",
        cwe         => "CWE-200",
        owasp       => "A05:2021",
        evidence    => join("\n", map { "$target/$_" } @exposed_manifests),
        remediation => "Block direct web access to /administrator/manifests/, /language/*.xml and README.txt (deny rules in the web server config).",
    );
}

# 6. Template manifest version disclosure (oracle: parse_template_manifest)
my @tmpl_manifest_hits;
foreach my $tpl (@{ extract_templates($vbody) || [] }) {
    my ($tcode, $tbody) = probe_url_with_root_fallback("templates/$tpl/templateDetails.xml");
    next if !defined $tcode || $tcode != 200 || is_soft404($tbody, $tcode);
    my $tver = parse_template_manifest($tbody);
    push @tmpl_manifest_hits, "$tpl $tver" if $tver ne "";
}
if (@tmpl_manifest_hits) {
    record_finding(
        title       => "Template version disclosure via readable templateDetails.xml",
        state       => "CONFIRMED",
        severity    => "LOW",
        cwe         => "CWE-200",
        owasp       => "A05:2021",
        evidence    => join("\n", map { "template $_" } @tmpl_manifest_hits),
        remediation => "Deny direct web access to /templates/*/templateDetails.xml or strip the <version> tag from publicly served manifests.",
    );
}

# 7. Composer dependency inventory disclosure (oracle: parse_composer_inventory)
my ($ccode, $cbody) = probe_url_with_root_fallback("libraries/vendor/composer/installed.json");
if (defined $ccode && $ccode == 200 && !is_soft404($cbody, $ccode)) {
    my $inventory = parse_composer_inventory($cbody);
    if (@$inventory) {
        record_finding(
            title       => "Composer dependency inventory publicly readable",
            state       => "CONFIRMED",
            severity    => "LOW",
            cwe         => "CWE-200",
            owasp       => "A05:2021",
            evidence    => scalar(@$inventory) . " packages disclosed (e.g. " . join(", ", @$inventory[0 .. ($#$inventory > 2 ? 2 : $#$inventory)]) . ")",
            remediation => "Block direct web access to /libraries/ (deny rule in the web server or .htaccess config).",
        );
    }
}

# 8. Template-position debug disclosure ?tp=1 (oracle: has_modline_disclosure)
{
    my ($pcode, $pbody) = probe_get("?tp=1");
    if (defined $pcode && $pcode == 200 && has_modline_disclosure($pbody)) {
        record_finding(
            title       => "Module position disclosure via ?tp=1 debug parameter",
            state       => "CONFIRMED",
            severity    => "INFO",
            cwe         => "CWE-200",
            owasp       => "A05:2021",
            evidence    => "$target/?tp=1 renders module-position outlines (modline markers)",
            remediation => "Set template 'Preview Module Positions' to disabled (global configuration) or block the tp query parameter.",
        );
    }
}

# 9. Unauthenticated content-history endpoints (oracle: looks_like_contenthistory)
{
    my @history_hits;
    foreach my $ep ('index.php?option=com_contenthistory', 'administrator/index.php?option=com_contenthistory') {
        my ($hcode, $hbody) = probe_get($ep);
        push @history_hits, $ep if defined $hcode && $hcode == 200 && looks_like_contenthistory($hbody);
    }
    if (@history_hits) {
        record_finding(
            title       => "Content-history endpoints readable without authentication",
            state       => "CONFIRMED",
            severity    => "MEDIUM",
            cwe         => "CWE-200",
            owasp       => "A01:2021",
            evidence    => join("\n", map { "$target/$_" } @history_hits),
            remediation => "Restrict com_contenthistory to authenticated users with the core.edit.own permission (ACL) and upgrade Joomla - unauthenticated history reads are fixed on supported series.",
        );
    }
}

# 10. Session-state header leakage to shared caches (oracle: validate_session_headers)
{
    my $sess = validate_session_headers($hres);
    my @leaked = grep { $_->{status} eq "disclosed" } @$sess;
    if (@leaked) {
        record_finding(
            title       => "Session-state header disclosed on public pages",
            state       => "CONFIRMED",
            severity    => "LOW",
            cwe         => "CWE-200",
            owasp       => "A05:2021",
            evidence    => join(", ", map { "$_->{header}: $_->{value}" } @leaked),
            remediation => "Strip X-Logged-In (and similar session headers) from responses sent to anonymous visitors, or mark responses private so shared caches never store them.",
        );
    }
}

tprint("Deterministic validation layer: " . scalar(@FINDINGS) . " structured finding(s) recorded - see findings.json in the report directory");
1;

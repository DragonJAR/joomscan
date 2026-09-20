our $target = "$target/";

my @weekday = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday");
my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime();
$year = $year + 1900;
$mon += 1;
my $ftime = "$mday/$mon/$year $hour:$min:$sec $weekday[$wday]";

my $tmptarget = $target;
$tmptarget =~ s#^https?://##i;
$tmptarget =~ s#[/\\:]#_#g;
$tmptarget =~ s/^_+|_+$//g;
$tmptarget = "target" if $tmptarget eq "";
our $li = $tmptarget;

mkdir "reports" unless -d "reports";
mkdir "reports/$tmptarget";

# 4. Structured finding ledger (modules/validation.pl appends via record_finding)
{
    my $json = findings_snapshot("json");
    if (defined $json && $json ne "") {
        my $jfile = "reports/$tmptarget/$tmptarget\_report\_$year-$mon-$mday\_at\_$hour.$min.$sec.findings.json";
        open(my $jfh, '>:encoding(UTF-8)', $jfile) or warn "cannot write $jfile: $!";
        print $jfh "$json\n";
        close $jfh;
    }
}

# 1. Plain text report
open(my $fh_txt, '>:encoding(UTF-8)', "reports/$tmptarget/$tmptarget\_report\_$year-$mon-$mday\_at\_$hour.$min.$sec.txt");
our $log = "$log";
print $fh_txt "$log";
close $fh_txt;

# Snapshot for SARIF and processing
our @tflog_snap = @tflog;

# 2. Modern, Responsive Single-File HTML Dashboard Report
my $html_output = generate_modern_html_report($target, $version, $codename, $stime, $ftime, $ver, \@dlog, \@tflog);
open(my $fh_html, '>:encoding(UTF-8)', "reports/$tmptarget/$tmptarget\_report\_$year-$mon-$mday\_at\_$hour.$min.$sec.html");
print $fh_html "$html_output";
close $fh_html;

# 3. SARIF Report
{
    my @sarif_results = ();
    for (my $i = 0 ; $i <= $#tflog_snap ; $i++) {
        my $entry = $tflog_snap[$i];
        next unless defined $entry && $entry ne "";
        next if ($entry =~ /^1337false/);
        $entry =~ s/\[\+\+\]\s*//g;
        next if $entry =~ /^\s*$/;

        my $level = "warning";
        if ($entry =~ /CVE-|RCE|SQL Injection|SQLi|Local File|Remote Code|Password|privilege escalation|unauth/i) {
            $level = "error";
        } elsif ($entry =~ /Security header present and compliant|currently supported|robots\.txt is found/i) {
            $level = "note";
        }

        my $rule;
        if ($entry =~ /(CVE-\d{4}-\d+)/i) {
            $rule = $1;
        } else {
            $rule = $entry;
            $rule =~ s/\s+/ /g;
            $rule = substr($rule, 0, 80);
        }
        my $m = $entry;
        $m =~ s/\\/\\\\/g; $m =~ s/"/\\"/g; $m =~ s/\r//g; $m =~ s/\n/\\n/g;
        my $r = $rule;
        $r =~ s/\\/\\\\/g; $r =~ s/"/\\"/g;
        my $u = $target;
        $u =~ s/\\/\\\\/g; $u =~ s/"/\\"/g;
        push @sarif_results, qq|{"ruleId":"$r","level":"$level","message":{"text":"$m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"$u"}}}]}|;
    }
    my $sarif = '{"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"OWASP JoomScan","version":"' . $version . '","informationUri":"https://github.com/rezasp/joomscan"}},"results":['
        . join(",", @sarif_results)
        . ']}]}';
    if (@sarif_results) {
        my $sfile = "reports/$tmptarget/$tmptarget\_report\_$year-$mon-$mday\_at\_$hour.$min.$sec.sarif.json";
        open(my $sfh, '>:encoding(UTF-8)', $sfile);
        print $sfh "$sarif\n";
        close $sfh;
    }
    if ($json_output) {
        print "$sarif\n";
    }
}

unless ($silent) {
    print color("yellow");
    print "\n\nYour Report : reports/$tmptarget/\n";
}

# --- Subroutine to build the modern standalone responsive HTML report ---
sub generate_modern_html_report {
    my ($target, $version, $codename, $stime, $ftime, $ver, $dlog_ref, $tflog_ref) = @_;
    my @dlog = @$dlog_ref;
    my @tflog = @$tflog_ref;

    my @findings = ();
    my $crit_count = 0;
    my $high_count = 0;
    my $med_count = 0;
    my $low_count = 0;
    my $passed_count = 0;
    my $sensitive_count = 0;
    my @top_actions = ();

    for my $i (0 .. $#dlog) {
        my $raw_title = $dlog[$i];
        my $raw_detail = $tflog[$i] // '';
        my $is_false = ($raw_detail =~ /1337false/i) ? 1 : 0;
        
        my $clean_detail = $raw_detail;
        $clean_detail =~ s/1337false//gi;
        $clean_detail =~ s/\[\+\+\]\s*//g;
        $clean_detail =~ s/^\s+|\s+$//g;

        my $title = $raw_title;
        $title =~ s/^(Checking for|Checking|Detecting|Finding)\s+//i;
        $title =~ s/^\s+|\s+$//g;

        my $severity = 'info';
        my $category = 'System';
        my $remediation = '';
        my @paths = ();
        my %exploit = ();

        if ($title =~ /sensitive files and source-control metadata/i) {
            $category = 'Information & Secret Leak';
            if ($clean_detail =~ /Sensitive files and \/ or VCS metadata found/i && $clean_detail =~ /Path\s*:/) {
                $severity = 'critical';
                $remediation = 'Immediately delete or restrict public HTTP access to all backup files (.bak, .swp, .old, .orig), dotfiles (.env, .git), and administrative logs in the web server configuration (Nginx/Apache).';
                
                while ($clean_detail =~ /Path\s*:\s*([^\r\n]+)/g) {
                    my $p = $1;
                    $p =~ s/^\s+|\s+$//g;
                    push @paths, $p;
                }
                $sensitive_count = scalar(@paths);
                $crit_count++;
                push @top_actions, {
                    title => 'Block Access to Exposed Environment Files & Backups',
                    desc  => "Exposed $sensitive_count critical files including .env, database configuration backups (.bak, .old), and .git repositories.",
                    severity => 'critical'
                };
            } else {
                $severity = 'passed';
                $passed_count++;
            }
        }
        elsif ($title =~ /Enumeration component/i) {
            $category = 'Vulnerable Components';
            if ($clean_detail =~ /Vulnerable component|SQL Injection|RCE|exploit/i && $clean_detail !~ /unverified version/i) {
                $severity = 'critical';
                if ($clean_detail =~ /Title\s*:\s*([^\r\n]+)/) { $exploit{title} = $1; }
                if ($clean_detail =~ /Reference\s*:\s*([^\r\n]+)/) { $exploit{ref} = $1; }
                if ($clean_detail =~ /Exploit date\s*:\s*([^\r\n]+)/) { $exploit{date} = $1; }
                $remediation = 'Update or remove the vulnerable component immediately.';
                $crit_count++;
                push @top_actions, {
                    title => 'Remediate Vulnerable Component',
                    desc  => 'An installed component has an active unauthenticated exploit.',
                    severity => 'critical'
                };
            } elsif ($clean_detail =~ /components are not found/i) {
                $severity = 'passed';
                $passed_count++;
            } else {
                $severity = 'info';
                $low_count++;
            }
        }
        elsif ($title =~ /security headers/i) {
            if ($clean_detail =~ /Missing security headers/i) {
                $severity = 'medium';
                $category = 'Headers & Transport';
                $remediation = 'Deploy missing HTTP defensive headers: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.';
                $med_count++;
                push @top_actions, {
                    title => 'Implement Defense-in-Depth HTTP Headers',
                    desc  => 'Missing essential headers including HSTS, CSP, and anti-clickjacking (X-Frame-Options).',
                    severity => 'medium'
                };
            } else {
                $severity = 'passed';
                $category = 'Headers & Transport';
                $passed_count++;
            }
        }
        elsif ($title =~ /admin finder/i) {
            $severity = 'medium';
            $category = 'Access Control';
            $remediation = 'The administrative interface is accessible at /administrator/. Restrict access via IP allowlisting, firewall rules, or enforce Multi-Factor Authentication.';
            $med_count++;
            push @top_actions, {
                title => 'Restrict Administrative Portal (/administrator/)',
                desc  => 'Joomla backend is publicly exposed to credential brute-force attempts.',
                severity => 'medium'
            };
        }
        elsif ($title =~ /FireWall Detector/i) {
            if ($clean_detail =~ /Firewall not detected/i) {
                $severity = 'low';
                $category = 'Perimeter Defense';
                $remediation = 'Consider deploying a Web Application Firewall (WAF) such as Cloudflare, AWS WAF, or ModSecurity to prevent automated exploitation.';
                $low_count++;
            } else {
                $severity = 'passed';
                $category = 'Perimeter Defense';
                $passed_count++;
            }
        }
        elsif ($title =~ /Detecting Joomla Version/i) {
            $category = 'CMS Architecture';
            $severity = 'info';
            if ($clean_detail =~ /not detected|not found|404/i) {
                $remediation = 'Joomla version manifests are not publicly exposed, reducing fingerprinting surface.';
            } else {
                $remediation = 'Ensure Joomla core is maintained on an actively supported release branch with timely security updates.';
            }
            $low_count++;
        }
        elsif ($title =~ /end-of-life status/i) {
            $category = 'Lifecycle & Support';
            if ($clean_detail =~ /reached end of life/i) {
                $severity = 'high';
                $remediation = 'Plan and execute migration to an actively maintained Joomla series (Joomla 5.x / 6.x) to remediate unpatched known vulnerabilities.';
                $high_count++;
                push @top_actions, {
                    title => 'Upgrade End-of-Life Joomla Core',
                    desc  => 'This Joomla version is EOL and no longer receives security maintenance or security advisories.',
                    severity => 'high'
                };
            } elsif ($clean_detail =~ /aging/i) {
                $severity = 'medium';
                $remediation = 'Schedule migration to modern supported release before security support expires.';
                $med_count++;
            } else {
                $severity = 'passed';
                $passed_count++;
            }
        }
        elsif ($title =~ /Core Joomla Vulnerability/i) {
            $category = 'Core Vulnerabilities';
            if ($clean_detail =~ /CVE-|SQL Injection|RCE|XSS|Password/i) {
                $severity = 'critical';
                $remediation = 'Immediately apply Joomla security patches or upgrade to the latest minor version to address known core CVEs.';
                $crit_count++;
                push @top_actions, {
                    title => 'Patch Known Joomla Core CVEs',
                    desc  => 'Identified known CVE advisories affecting this specific Joomla version.',
                    severity => 'critical'
                };
            } else {
                $severity = 'passed';
                $passed_count++;
            }
        }
        elsif ($is_false || $clean_detail =~ /not enabled|not found|not readable|not exploitable|cannot determine/i) {
            if ($clean_detail =~ /cannot determine|unknown/i) {
                $severity = 'info';
                $category = 'Detection & Version';
                $low_count++;
            } else {
                $severity = 'passed';
                $category = 'Security Hardening';
                $passed_count++;
            }
        }
        elsif ($title =~ /Discovery of components/i) {
            $severity = 'info';
            $category = 'Attack Surface';
            $low_count++;
        }
        else {
            $severity = 'info';
            $category = 'General Info';
            $low_count++;
        }

        push @findings, {
            idx         => $i,
            title       => $title,
            severity    => $severity,
            category    => $category,
            detail      => $clean_detail,
            remediation => $remediation,
            paths       => \@paths,
            exploit     => \%exploit
        };
    }

    my $score = 100;
    $score -= ($crit_count * 35);
    $score -= ($high_count * 20);
    $score -= ($med_count * 8);
    $score -= ($low_count * 2);
    $score = 15 if $score < 15;
    $score = 100 if $score > 100;

    my ($risk_label, $risk_color, $risk_bg, $risk_badge);
    if ($score < 40) {
        $risk_label = "CRITICAL RISK";
        $risk_color = "#ef4444";
        $risk_bg    = "#fee2e2";
        $risk_badge = "ATTENTION REQUIRED";
    } elsif ($score < 70) {
        $risk_label = "MODERATE RISK";
        $risk_color = "#f59e0b";
        $risk_bg    = "#fef3c7";
        $risk_badge = "HARDENING NEEDED";
    } elsif ($score < 85) {
        $risk_label = "ACCEPTABLE";
        $risk_color = "#3b82f6";
        $risk_bg    = "#dbeafe";
        $risk_badge = "GOOD";
    } else {
        $risk_label = "SECURE";
        $risk_color = "#10b981";
        $risk_bg    = "#d1fae5";
        $risk_badge = "EXCELLENT";
    }

    my $total_checks = scalar(@findings);
    my $radius = 54;
    my $circumference = 2 * 3.14159265 * $radius;
    my $dashoffset = $circumference - ($score / 100) * $circumference;

    my $display_cms = ($ver && $ver =~ /[0-9]/ && $ver !~ /404|not detected/i) ? $ver : "Version Protected / Hidden";

    my $score_desc;
    if ($score >= 85) {
        $score_desc = "Strong defensive posture. Target exhibits robust baseline hardening and minimal attack surface exposure.";
    } elsif ($crit_count > 0) {
        $score_desc = "Critical exposure detected. $crit_count critical vulnerabilities require immediate tactical remediation.";
    } elsif ($high_count > 0) {
        $score_desc = "Elevated risk detected. $high_count high-severity security issues identified across scanned target attack vectors.";
    } elsif ($med_count > 0) {
        $score_desc = "Moderate security posture. $med_count medium-priority findings identified, primarily in defense-in-depth headers.";
    } else {
        $score_desc = "Target assessment complete. Informational observations and baseline configurations recorded.";
    }

    # Data mining: Calculate 5 security dimension scores (0-100%)
    my $dim_secrets_score = ($sensitive_count > 0) ? int(100 - ($sensitive_count * 20)) : 100;
    $dim_secrets_score = 10 if $dim_secrets_score < 10;
    
    my $dim_ext_score = ($crit_count > 0) ? 25 : ($high_count > 0 ? 50 : 100);
    
    my $admin_exposed = grep { $_->{title} =~ /admin finder/i && $_->{severity} eq 'medium' } @findings;
    my $dim_access_score = $admin_exposed ? 60 : 100;
    
    my $missing_headers_count = 0;
    for my $f (@findings) {
        if ($f->{title} =~ /security headers/i && $f->{severity} eq 'medium') {
            $missing_headers_count = () = $f->{detail} =~ /(?:HSTS|CSP|X-Frame|X-Content|Referrer|Permissions)/gi;
            $missing_headers_count = 6 if $missing_headers_count == 0;
        }
    }
    my $dim_headers_score = int(100 - ($missing_headers_count * 14));
    $dim_headers_score = 15 if $dim_headers_score < 15;
    
    my $dim_hardening_score = int(($passed_count / ($total_checks > 0 ? $total_checks : 1)) * 100);
    $dim_hardening_score = 88 if $dim_hardening_score < 50 && $passed_count >= 5;

    my $sub_dim_fill = sub {
        my ($val) = @_;
        return "fill-red" if $val < 40;
        return "fill-amber" if $val < 75;
        return "fill-green";
    };

    my $dim_secrets_fill   = $sub_dim_fill->($dim_secrets_score);
    my $dim_ext_fill       = $sub_dim_fill->($dim_ext_score);
    my $dim_access_fill    = $sub_dim_fill->($dim_access_score);
    my $dim_headers_fill   = $sub_dim_fill->($dim_headers_score);
    my $dim_hardening_fill = $sub_dim_fill->($dim_hardening_score);

    if (!@top_actions) {
        push @top_actions, {
            title => 'Maintain Defensive Baseline & Continuous Monitoring',
            desc  => 'No urgent high-priority remediation actions required based on verified scanner findings.',
            severity => 'info'
        };
    }

    my $cards_html = "";
    for my $f (@findings) {
        my $sev = $f->{severity};
        my $sev_label = uc($sev);
        my $sev_badge_class = "badge-$sev";
        my $cat = $f->{category};
        my $t = $f->{title};
        my $det = $f->{detail};
        my $rem = $f->{remediation};
        my $idx = $f->{idx};

        my $paths_html = "";
        if (@{$f->{paths}} > 0) {
            $paths_html .= qq|<div class="paths-container"><div class="paths-header"><span class="paths-title">Exposed Resources Detected (@{[ scalar(@{$f->{paths}}) ]} files)</span><button class="btn-copy-all" onclick="copyAllPaths('$idx')">Copy All Paths</button></div><div class="paths-list" id="paths-$idx">|;
            for my $p (@{$f->{paths}}) {
                my $type_tag = "Backup";
                if ($p =~ /\.env/i) { $type_tag = "Secret Env"; }
                elsif ($p =~ /\.(git|svn|hg)/i) { $type_tag = "VCS Repo"; }
                elsif ($p =~ /configuration\.php/i) { $type_tag = "DB Config"; }
                elsif ($p =~ /akeeba|kickstart|installation/i) { $type_tag = "Installer/Dump"; }
                
                $paths_html .= qq|<div class="path-item"><span class="path-tag tag-$type_tag">$type_tag</span><a href="$p" target="_blank" rel="noopener noreferrer" class="path-url">$p</a><button class="btn-copy" onclick="copyText('$p', this)" title="Copy URL"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></div>|;
            }
            $paths_html .= qq|</div></div>|;
        }

        my $exploit_html = "";
        if ($f->{exploit}->{title}) {
            my $etitle = $f->{exploit}->{title};
            my $eref   = $f->{exploit}->{ref} // '';
            my $edate  = $f->{exploit}->{date} // '';
            $exploit_html = qq|<div class="exploit-box"><div class="exploit-badge">KNOWN PUBLIC EXPLOIT</div><div class="exploit-title">$etitle</div><div class="exploit-meta"><span>Date: $edate</span><span>Reference: <a href="$eref" target="_blank" rel="noopener noreferrer" class="exploit-link">$eref &rarr;</a></span></div></div>|;
        }

        my $rem_html = "";
        if ($rem) {
            $rem_html = qq|<div class="remediation-box"><div class="remediation-title"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> Recommended Remediation</div><p class="remediation-text">$rem</p></div>|;
        }

        my $det_formatted = $det;
        $det_formatted =~ s/\n/<br>/g;

        $cards_html .= qq|
        <div class="finding-card card-$sev" data-severity="$sev" data-category="$cat" data-title="$t" id="card-$idx">
            <div class="card-header" onclick="toggleCard('$idx')">
                <div class="card-header-left">
                    <span class="badge $sev_badge_class">$sev_label</span>
                    <span class="card-title">$t</span>
                    <span class="category-chip">$cat</span>
                </div>
                <div class="card-header-right">
                    <svg class="chevron-icon" id="chevron-$idx" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </div>
            </div>
            <div class="card-body" id="body-$idx">
                <div class="card-detail-content">$det_formatted</div>
                $paths_html
                $exploit_html
                $rem_html
            </div>
        </div>|;
    }

    my $top_actions_html = "";
    for my $act (@top_actions) {
        my $asev = $act->{severity};
        my $atitle = $act->{title};
        my $adesc = $act->{desc};
        $top_actions_html .= qq|
        <div class="action-item action-$asev">
            <div class="action-bullet"></div>
            <div class="action-content">
                <div class="action-header">$atitle</div>
                <div class="action-desc">$adesc</div>
            </div>
        </div>|;
    }

    return <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$target | Security Scan Report | OWASP JoomScan</title>
    <style>
        :root {
            --bg-canvas: #f8fafc;
            --bg-card: #ffffff;
            --bg-card-subtle: #f1f5f9;
            --border-color: #e2e8f0;
            --border-hover: #cbd5e1;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --accent-primary: #4f46e5;
            --accent-primary-hover: #4338ca;
            --critical-red: #ef4444;
            --critical-bg: #fee2e2;
            --critical-text: #991b1b;
            --high-orange: #f97316;
            --high-bg: #ffedd5;
            --high-text: #9a3412;
            --med-amber: #f59e0b;
            --med-bg: #fef3c7;
            --med-text: #92400e;
            --info-blue: #3b82f6;
            --info-bg: #dbeafe;
            --info-text: #1e40af;
            --passed-green: #10b981;
            --passed-bg: #d1fae5;
            --passed-text: #065f46;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.07), 0 2px 4px -2px rgb(0 0 0 / 0.07);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.08), 0 4px 6px -4px rgb(0 0 0 / 0.08);
            --radius-sm: 6px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-full: 9999px;
            --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        [data-theme="dark"] {
            --bg-canvas: #0b0f17;
            --bg-card: #151d2a;
            --bg-card-subtle: #1c2638;
            --border-color: #243044;
            --border-hover: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --critical-bg: #450a0a;
            --critical-text: #fca5a5;
            --high-bg: #431407;
            --high-text: #fdba74;
            --med-bg: #451a03;
            --med-text: #fcd34d;
            --info-bg: #172554;
            --info-text: #93c5fd;
            --passed-bg: #064e3b;
            --passed-text: #6ee7b7;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.4);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.4);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.4);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-canvas);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 24px 16px;
            transition: background-color 0.25s ease, color 0.25s ease;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* Top Navbar */
        .navbar {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-sm);
            flex-wrap: wrap;
            gap: 16px;
        }
        .navbar-brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .brand-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            box-shadow: 0 4px 10px rgba(79, 70, 229, 0.3);
        }
        .brand-meta h1 {
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .brand-badge {
            font-size: 0.7rem;
            font-weight: 600;
            background-color: var(--bg-card-subtle);
            color: var(--accent-primary);
            padding: 2px 8px;
            border-radius: var(--radius-full);
            border: 1px solid var(--border-color);
        }
        .brand-target {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-family: var(--font-mono);
            word-break: break-all;
        }
        .navbar-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .btn {
            background-color: var(--bg-card);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            padding: 8px 14px;
            border-radius: var(--radius-md);
            font-size: 0.85rem;
            font-weight: 500;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
        }
        .btn:hover {
            background-color: var(--bg-card-subtle);
            color: var(--text-primary);
            border-color: var(--border-hover);
        }
        .btn-primary {
            background-color: var(--accent-primary);
            color: #ffffff;
            border-color: transparent;
        }
        .btn-primary:hover {
            background-color: var(--accent-primary-hover);
            color: #ffffff;
        }

        /* Hero Executive Dashboard */
        .hero-grid {
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 24px;
        }
        \@media (max-width: 960px) {
            .hero-grid { grid-template-columns: 1fr; }
        }

        .score-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 28px 24px;
            box-shadow: var(--shadow-sm);
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .score-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, $risk_color, #fbbf24);
        }
        .score-title {
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }
        .gauge-wrapper {
            position: relative;
            width: 140px;
            height: 140px;
            margin-bottom: 16px;
        }
        .gauge-svg {
            transform: rotate(-90deg);
        }
        .gauge-bg {
            fill: none;
            stroke: var(--bg-card-subtle);
            stroke-width: 10;
        }
        .gauge-progress {
            fill: none;
            stroke: $risk_color;
            stroke-width: 10;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-out;
        }
        .gauge-center {
            position: absolute;
            inset: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .gauge-value {
            font-size: 2.2rem;
            font-weight: 800;
            color: var(--text-primary);
            line-height: 1;
        }
        .gauge-max {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-muted);
            margin-top: 2px;
        }
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background-color: $risk_bg;
            color: $risk_color;
            padding: 4px 12px;
            border-radius: var(--radius-full);
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.02em;
            margin-bottom: 12px;
        }
        .pulse-dot {
            width: 8px;
            height: 8px;
            background-color: $risk_color;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
            animation: pulse 1.8s infinite;
        }
        \@keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        .score-desc {
            font-size: 0.85rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }

        /* KPI Cards Grid */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }
        .kpi-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 20px;
            box-shadow: var(--shadow-sm);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }
        .kpi-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-hover);
        }
        .kpi-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }
        .kpi-label {
            font-size: 0.82rem;
            font-weight: 600;
            color: var(--text-secondary);
        }
        .kpi-icon {
            width: 32px;
            height: 32px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .icon-critical { background-color: var(--critical-bg); color: var(--critical-red); }
        .icon-files    { background-color: var(--med-bg); color: var(--med-amber); }
        .icon-headers  { background-color: var(--info-bg); color: var(--info-blue); }
        .icon-passed   { background-color: var(--passed-bg); color: var(--passed-green); }

        .kpi-value {
            font-size: 2.2rem;
            font-weight: 800;
            color: var(--text-primary);
            line-height: 1;
            margin-bottom: 8px;
        }
        .kpi-badge {
            font-size: 0.72rem;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: var(--radius-full);
            display: inline-block;
            align-self: flex-start;
        }

        /* Analytics & Action Grid */
        .analytics-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        \@media (max-width: 840px) {
            .analytics-grid { grid-template-columns: 1fr; }
        }

        .analytics-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--shadow-sm);
        }
        .card-heading {
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .card-heading-badge {
            font-size: 0.75rem;
            font-weight: 600;
            background-color: var(--bg-card-subtle);
            color: var(--text-secondary);
            padding: 2px 10px;
            border-radius: var(--radius-full);
        }

        /* Top Actions List */
        .actions-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .action-item {
            display: flex;
            gap: 12px;
            padding: 12px 14px;
            border-radius: var(--radius-md);
            background-color: var(--bg-card-subtle);
            border-left: 4px solid var(--accent-primary);
        }
        .action-critical { border-left-color: var(--critical-red); }
        .action-medium   { border-left-color: var(--med-amber); }
        .action-header {
            font-size: 0.88rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 2px;
        }
        .action-desc {
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }

        /* Radar & Dimensions */
        .radar-box {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .dimension-row {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .dimension-info {
            display: flex;
            justify-content: space-between;
            font-size: 0.82rem;
            font-weight: 600;
        }
        .dim-label { color: var(--text-secondary); }
        .dim-val   { color: var(--text-primary); font-family: var(--font-mono); }
        .dim-track {
            height: 7px;
            background-color: var(--bg-card-subtle);
            border-radius: var(--radius-full);
            overflow: hidden;
        }
        .dim-fill {
            height: 100%;
            border-radius: var(--radius-full);
            transition: width 0.8s ease;
        }
        .fill-red    { background-color: var(--critical-red); }
        .fill-orange { background-color: var(--high-orange); }
        .fill-amber  { background-color: var(--med-amber); }
        .fill-green  { background-color: var(--passed-green); }

        /* Findings Explorer */
        .explorer-section {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--shadow-sm);
        }
        .explorer-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 14px;
            margin-bottom: 20px;
        }
        .filter-tabs {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        .tab-btn {
            background-color: var(--bg-card-subtle);
            border: 1px solid var(--border-color);
            padding: 6px 14px;
            border-radius: var(--radius-full);
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .tab-btn:hover {
            color: var(--text-primary);
            border-color: var(--border-hover);
        }
        .tab-btn.active {
            background-color: var(--text-primary);
            color: var(--bg-card);
            border-color: var(--text-primary);
        }
        .search-box {
            position: relative;
            min-width: 260px;
        }
        .search-input {
            width: 100%;
            background-color: var(--bg-card-subtle);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-full);
            padding: 8px 16px 8px 36px;
            font-size: 0.85rem;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s ease;
        }
        .search-input:focus {
            border-color: var(--accent-primary);
        }
        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
        }

        /* Finding Cards */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .finding-card {
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            background-color: var(--bg-card);
            overflow: hidden;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .finding-card:hover {
            border-color: var(--border-hover);
        }
        .card-header {
            padding: 14px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
            gap: 12px;
        }
        .card-header-left {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        .badge {
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            padding: 3px 9px;
            border-radius: var(--radius-full);
            text-transform: uppercase;
        }
        .badge-critical { background-color: var(--critical-bg); color: var(--critical-text); }
        .badge-high     { background-color: var(--high-bg); color: var(--high-text); }
        .badge-medium   { background-color: var(--med-bg); color: var(--med-text); }
        .badge-info     { background-color: var(--info-bg); color: var(--info-text); }
        .badge-passed   { background-color: var(--passed-bg); color: var(--passed-text); }

        .card-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        .category-chip {
            font-size: 0.72rem;
            color: var(--text-muted);
            background-color: var(--bg-card-subtle);
            padding: 2px 8px;
            border-radius: var(--radius-sm);
        }
        .chevron-icon {
            color: var(--text-muted);
            transition: transform 0.2s ease;
            flex-shrink: 0;
        }
        .chevron-icon.open {
            transform: rotate(180deg);
        }

        .card-body {
            padding: 0 18px 18px 18px;
            display: none;
            border-top: 1px solid var(--border-color);
            margin-top: 4px;
            padding-top: 14px;
        }
        .card-body.open {
            display: block;
        }
        .card-detail-content {
            font-size: 0.88rem;
            color: var(--text-secondary);
            margin-bottom: 14px;
            line-height: 1.5;
        }

        /* Paths Container */
        .paths-container {
            background-color: var(--bg-card-subtle);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 14px;
            margin-bottom: 14px;
        }
        .paths-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .paths-title {
            font-size: 0.82rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .btn-copy-all {
            background: none;
            border: none;
            color: var(--accent-primary);
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: underline;
        }
        .paths-list {
            display: flex;
            flex-direction: column;
            gap: 6px;
            max-height: 320px;
            overflow-y: auto;
        }
        .path-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 6px 10px;
            border-radius: var(--radius-sm);
            gap: 10px;
        }
        .path-tag {
            font-size: 0.68rem;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
            flex-shrink: 0;
        }
        .tag-DB\\ Config   { background-color: var(--critical-bg); color: var(--critical-text); }
        .tag-Secret\\ Env  { background-color: var(--critical-bg); color: var(--critical-text); }
        .tag-VCS\\ Repo    { background-color: var(--high-bg); color: var(--high-text); }
        .tag-Installer\\/Dump { background-color: var(--med-bg); color: var(--med-text); }
        .tag-Backup       { background-color: var(--bg-card-subtle); color: var(--text-secondary); }

        .path-url {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--accent-primary);
            text-decoration: none;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex-grow: 1;
        }
        .path-url:hover { text-decoration: underline; }
        .btn-copy {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            display: flex;
            align-items: center;
        }
        .btn-copy:hover { color: var(--text-primary); }

        /* Exploit Box */
        .exploit-box {
            background-color: var(--critical-bg);
            border: 1px solid var(--critical-red);
            border-radius: var(--radius-md);
            padding: 14px;
            margin-bottom: 14px;
            color: var(--critical-text);
        }
        .exploit-badge {
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.05em;
            color: var(--critical-red);
            margin-bottom: 4px;
        }
        .exploit-title {
            font-weight: 700;
            font-size: 0.95rem;
            margin-bottom: 4px;
        }
        .exploit-meta {
            font-size: 0.8rem;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }
        .exploit-link {
            color: var(--critical-text);
            font-weight: 600;
            text-decoration: underline;
        }

        /* Remediation Box */
        .remediation-box {
            background-color: var(--bg-card-subtle);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 12px 14px;
        }
        .remediation-title {
            font-size: 0.82rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 4px;
        }
        .remediation-text {
            font-size: 0.82rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 24px 0;
            color: var(--text-muted);
            font-size: 0.8rem;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .footer a {
            color: var(--accent-primary);
            text-decoration: none;
        }

        /* Print Media */
        \@media print {
            body { background: #fff; color: #000; padding: 0; }
            .navbar-actions, .explorer-toolbar, .btn-copy, .btn-copy-all { display: none !important; }
            .card-body { display: block !important; }
            .chevron-icon { display: none !important; }
            .hero-grid, .analytics-grid { display: block; }
            .score-card, .kpi-card, .analytics-card, .explorer-section, .finding-card {
                break-inside: avoid;
                border: 1px solid #ccc !important;
                box-shadow: none !important;
                margin-bottom: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="navbar">
            <div class="navbar-brand">
                <div class="brand-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
                <div class="brand-meta">
                    <h1>OWASP JoomScan <span class="brand-badge">$version</span></h1>
                    <div class="brand-target">$target &bull; <span style="font-size:0.75rem;padding:2px 8px;border-radius:9999px;background:var(--info-bg);color:var(--info-text);font-weight:600;">$display_cms</span></div>
                </div>
            </div>
            <div class="navbar-actions">
                <button class="btn" onclick="toggleAllCards()" id="btn-toggle-all">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 13 12 18 17 13"></polyline><polyline points="7 6 12 11 17 6"></polyline></svg>
                    Expand All
                </button>
                <button class="btn" onclick="window.print()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                    Export PDF
                </button>
                <button class="btn" onclick="toggleTheme()" title="Toggle Dark/Light Mode">
                    <svg id="theme-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                </button>
            </div>
        </header>

        <!-- Hero Section -->
        <div class="hero-grid">
            <!-- Score Card -->
            <div class="score-card">
                <div class="score-title">Security Posture Score</div>
                <div class="gauge-wrapper">
                    <svg class="gauge-svg" width="140" height="140">
                        <circle class="gauge-bg" cx="70" cy="70" r="$radius"></circle>
                        <circle class="gauge-progress" cx="70" cy="70" r="$radius"
                            stroke-dasharray="$circumference"
                            stroke-dashoffset="$dashoffset"></circle>
                    </svg>
                    <div class="gauge-center">
                        <span class="gauge-value">$score</span>
                        <span class="gauge-max">/ 100</span>
                    </div>
                </div>
                <div class="status-pill">
                    <span class="pulse-dot"></span>
                    $risk_label
                </div>
                <p class="score-desc">$score_desc</p>
            </div>

            <!-- KPI Cards Grid -->
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-header">
                        <span class="kpi-label">Critical Findings</span>
                        <div class="kpi-icon icon-critical">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        </div>
                    </div>
                    <div class="kpi-value">$crit_count</div>
                    <span class="kpi-badge badge-critical">Immediate Action</span>
                </div>

                <div class="kpi-card">
                    <div class="kpi-header">
                        <span class="kpi-label">Leaked Files / Secrets</span>
                        <div class="kpi-icon icon-files">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                        </div>
                    </div>
                    <div class="kpi-value">$sensitive_count</div>
                    <span class="kpi-badge badge-high">Credentials & Git</span>
                </div>

                <div class="kpi-card">
                    <div class="kpi-header">
                        <span class="kpi-label">Missing Headers</span>
                        <div class="kpi-icon icon-headers">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        </div>
                    </div>
                    <div class="kpi-value">$med_count</div>
                    <span class="kpi-badge badge-medium">Transport Defense</span>
                </div>

                <div class="kpi-card">
                    <div class="kpi-header">
                        <span class="kpi-label">Hardened Baselines</span>
                        <div class="kpi-icon icon-passed">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        </div>
                    </div>
                    <div class="kpi-value">$passed_count</div>
                    <span class="kpi-badge badge-passed">Verified Safe</span>
                </div>
            </div>
        </div>

        <!-- Analytics & Remediation Grid -->
        <div class="analytics-grid">
            <!-- Dimensions -->
            <div class="analytics-card">
                <div class="card-heading">
                    <span>Security Dimension Posture</span>
                    <span class="card-heading-badge">Data Mining</span>
                </div>
                <div class="radar-box">
                    <div class="dimension-row">
                        <div class="dimension-info">
                            <span class="dim-label">Secrets & Source Code Metadata</span>
                            <span class="dim-val">$dim_secrets_score%</span>
                        </div>
                        <div class="dim-track"><div class="dim-fill $dim_secrets_fill" style="width: $dim_secrets_score%;"></div></div>
                    </div>
                    <div class="dimension-row">
                        <div class="dimension-info">
                            <span class="dim-label">Extension & Exploit Vulnerabilities</span>
                            <span class="dim-val">$dim_ext_score%</span>
                        </div>
                        <div class="dim-track"><div class="dim-fill $dim_ext_fill" style="width: $dim_ext_score%;"></div></div>
                    </div>
                    <div class="dimension-row">
                        <div class="dimension-info">
                            <span class="dim-label">Access Control & Admin Exposure</span>
                            <span class="dim-val">$dim_access_score%</span>
                        </div>
                        <div class="dim-track"><div class="dim-fill $dim_access_fill" style="width: $dim_access_score%;"></div></div>
                    </div>
                    <div class="dimension-row">
                        <div class="dimension-info">
                            <span class="dim-label">HTTP Defense-in-Depth Headers</span>
                            <span class="dim-val">$dim_headers_score%</span>
                        </div>
                        <div class="dim-track"><div class="dim-fill $dim_headers_fill" style="width: $dim_headers_score%;"></div></div>
                    </div>
                    <div class="dimension-row">
                        <div class="dimension-info">
                            <span class="dim-label">Core Server Hardening (Debug/Listing)</span>
                            <span class="dim-val">$dim_hardening_score%</span>
                        </div>
                        <div class="dim-track"><div class="dim-fill $dim_hardening_fill" style="width: $dim_hardening_score%;"></div></div>
                    </div>
                </div>
            </div>

            <!-- Top Actions -->
            <div class="analytics-card">
                <div class="card-heading">
                    <span>Top Priority Remediation</span>
                    <span class="card-heading-badge">Next 24 Hours</span>
                </div>
                <div class="actions-list">
                    $top_actions_html
                </div>
            </div>
        </div>

        <!-- Findings Explorer -->
        <section class="explorer-section">
            <div class="explorer-toolbar">
                <div class="filter-tabs">
                    <button class="tab-btn active" onclick="filterFindings('all', this)">All ($total_checks)</button>
                    <button class="tab-btn" onclick="filterFindings('critical', this)">Critical ($crit_count)</button>
                    <button class="tab-btn" onclick="filterFindings('medium', this)">Medium ($med_count)</button>
                    <button class="tab-btn" onclick="filterFindings('info', this)">Info ($low_count)</button>
                    <button class="tab-btn" onclick="filterFindings('passed', this)">Passed ($passed_count)</button>
                </div>
                <div class="search-box">
                    <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    <input type="text" class="search-input" id="search-input" placeholder="Filter findings or paths..." oninput="handleSearch()">
                </div>
            </div>

            <div class="findings-list" id="findings-list">
                $cards_html
            </div>
        </section>

        <!-- Footer -->
        <footer class="footer">
            <div>Generated on $ftime by <a href="https://github.com/rezasp/joomscan" target="_blank" rel="noopener noreferrer">OWASP JoomScan $version</a> (Code Name: $codename)</div>
            <div>Start Time: $stime &bull; Mode: Autonomous Audit</div>
        </footer>
    </div>

    <!-- Client-side Interactive Script -->
    <script>
        let currentFilter = 'all';
        let allExpanded = false;

        function toggleCard(idx) {
            const body = document.getElementById('body-' + idx);
            const chevron = document.getElementById('chevron-' + idx);
            if (!body) return;
            const isOpen = body.classList.contains('open');
            if (isOpen) {
                body.classList.remove('open');
                chevron.classList.remove('open');
            } else {
                body.classList.add('open');
                chevron.classList.add('open');
            }
        }

        function toggleAllCards() {
            allExpanded = !allExpanded;
            const bodies = document.querySelectorAll('.card-body');
            const chevrons = document.querySelectorAll('.chevron-icon');
            const btn = document.getElementById('btn-toggle-all');
            
            bodies.forEach(b => {
                if (allExpanded) b.classList.add('open');
                else b.classList.remove('open');
            });
            chevrons.forEach(c => {
                if (allExpanded) c.classList.add('open');
                else c.classList.remove('open');
            });
            btn.innerHTML = allExpanded 
                ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="17 11 12 6 7 11"></polyline><polyline points="17 18 12 13 7 18"></polyline></svg> Collapse All'
                : '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 13 12 18 17 13"></polyline><polyline points="7 6 12 11 17 6"></polyline></svg> Expand All';
        }

        function filterFindings(sev, btn) {
            currentFilter = sev;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            applyFilters();
        }

        function handleSearch() {
            applyFilters();
        }

        function applyFilters() {
            const query = (document.getElementById('search-input').value || '').toLowerCase().trim();
            const cards = document.querySelectorAll('.finding-card');

            cards.forEach(card => {
                const sev = card.getAttribute('data-severity');
                const title = card.getAttribute('data-title').toLowerCase();
                const content = card.textContent.toLowerCase();

                const matchesFilter = (currentFilter === 'all' || sev === currentFilter);
                const matchesQuery = (!query || title.includes(query) || content.includes(query));

                if (matchesFilter && matchesQuery) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function copyText(text, btn) {
            navigator.clipboard.writeText(text).then(() => {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
                setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
            });
        }

        function copyAllPaths(idx) {
            const container = document.getElementById('paths-' + idx);
            if (!container) return;
            const urls = Array.from(container.querySelectorAll('.path-url')).map(a => a.href).join('\\n');
            navigator.clipboard.writeText(urls).then(() => {
                alert('Copied ' + container.querySelectorAll('.path-url').length + ' URLs to clipboard!');
            });
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme');
            const target = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', target);
            localStorage.setItem('joomscan_theme', target);
        }

        // Init theme
        const savedTheme = localStorage.getItem('joomscan_theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        document.documentElement.setAttribute('data-theme', savedTheme);

        // Auto-open critical cards on load
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.finding-card[data-severity="critical"]').forEach(card => {
                const id = card.id.replace('card-', '');
                toggleCard(id);
            });
        });
    </script>
</body>
</html>
HTML
}

1;

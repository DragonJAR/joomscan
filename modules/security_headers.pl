dprint("Checking security headers");

do "$mepath/core/lib.pl";

my %want = (
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

my $hres = $ua->get("$target/");
my $missing = "";
my $weak = "";
foreach my $h (sort keys %want){
    my $v = $hres->header($h);
    if(defined $v && $v ne ""){
        if($v =~ $want{$h}{pattern}){
            tprint("Security header present and compliant : $h => $v");
        }else{
            $weak .= "$h => $v\n";
            tprint("Security header present but weak : $h => $v (" . $want{$h}{okay} . ")");
        }
    }else{
        $missing .= "$h (" . $want{$h}{desc} . ")\n";
    }
}
if($missing){
    fprint("Missing security headers ("
          . $missing
          . ") - add them in the web server or .htaccess config");
}
if(!$missing and !$weak){
    tprint("All baseline security headers are present and compliant");
}

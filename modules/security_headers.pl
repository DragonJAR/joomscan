dprint("Checking security headers");

do "$mepath/core/lib.pl";

# Header verdicts come from the shared %SECURITY_HEADERS table and validate_headers
# oracle in core/lib.pl (single source of truth, also consumed by modules/validation.pl
# and t/07_validation.t). probe_get reuses the cached homepage response.
my ($hprobe_code, $hprobe_body) = probe_get("");
my $hres = $resp_cache{"$target/"} // $resp_cache{$target};
my $missing = "";
my $weak = "";
foreach my $verdict (@{ validate_headers($hres) }){
    my $h = $verdict->{header};
    my $v = $verdict->{value};
    if($verdict->{status} eq "compliant"){
        tprint("Security header present and compliant : $h => $v");
    }elsif($verdict->{status} eq "weak"){
        $weak .= "$h => $v\n";
        tprint("Security header present but weak : $h => $v (" . $SECURITY_HEADERS{$h}{okay} . ")");
    }else{
        $missing .= "$h (" . $SECURITY_HEADERS{$h}{desc} . ")\n";
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

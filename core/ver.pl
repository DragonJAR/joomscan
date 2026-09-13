dprint("Detecting Joomla Version");

do "$mepath/core/lib.pl";

$ver = "";
my ($alive_code) = probe_get("");
if ($alive_code == 0) {
    unless($silent){
        print color("red");
        print "[++] The target is not alive!\n\n";
        print color("reset");
    }
    if (!$urlfile) { exit 0; } else { next; }
}

$ver = detect_joomla_version($target);
$ver =~ s/[^0-9a-zA-Z. \-()]//g;

if ($ver =~ /[0-9]/) {
    tprint("$ver");
} else {
    fprint("Version not detected (protected or obscured)\n");
}

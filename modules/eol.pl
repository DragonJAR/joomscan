dprint("Checking Joomla end-of-life status");

do "$mepath/core/lib.pl";

my $jvnum = joomla_version_num($ver);
if($jvnum eq ""){
    fprint("Cannot determine EOL status - Joomla version unknown");
}else{
    my $s = eol_series_for($jvnum);
    if(!$s){
        fprint("Joomla $jvnum is not a recognized release series");
    }else{
        my $status = jsupport_status($jvnum);
        if($status eq "eol"){
            fprint("This Joomla version ($jvnum) reached end of life on $s->[4] - it no longer receives security updates and is exposed to unpatched vulnerabilities. Upgrade to a supported series (latest: Joomla 6.x / 5.4.x).");
        }elsif($status eq "aging"){
            tprint("Joomla $jvnum is in the aging series $s->[0] - active support ended $s->[3], security support ends $s->[4]. Plan an upgrade to Joomla 6.x.");
        }else{
            tprint("Joomla $jvnum is currently supported (series $s->[0], security support until $s->[4]).");
        }
    }
}

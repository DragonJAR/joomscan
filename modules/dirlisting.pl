dprint("Checking directory listing and target response behaviour");

do "$mepath/core/lib.pl";

my $status_msg = "";
my ($code404, $body404) = probe_get("thispathdoesnotexist12345");
if($code404 == 200 && is_soft404($body404, $code404)){
    $status_msg = "Target returns HTTP 200 for non-existent paths (soft-404) - baseline calibration active.\n";
}

my @dirl = ('administrator/components','components','administrator/modules','modules',
            'administrator/templates','templates','cache','images','includes','language',
            'media','tmp','images/stories','images/banners');
my $idx="";
foreach my $dir (@dirl){
    my ($code, $body) = probe_get("$dir/");
    next unless $code == 200;
    next if is_soft404($body, $code);
    if($body =~ /<title>Index of/i or $body =~ /Last modified<\/a>/i or $body =~ /Parent Directory<\/a>/i){
        $idx .= "$target/$dir/\n";
    }
}
if($idx){
    tprint($status_msg . "Directories with index listing enabled : \n$idx");
}else{
    fprint($status_msg . "Directory listing is not enabled");
}

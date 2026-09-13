#start Directory List & 404 handling
# DRY: soft-404 classification lives in core/lib.pl and is shared by all
# modules that probe paths; here we only consume it.
dprint("Checking directory listing and target response behaviour");

do "$mepath/core/lib.pl";

# Classify the "not found" body once for diagnostics, then reuse the helper.
my ($code404, $body404) = probe_get("thispathdoesnotexist12345");
if($code404 == 200 && is_soft404($body404, $code404)){
    fprint("Target returns HTTP 200 for non-existent paths (soft-404) - path checks may have false positives");
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
    tprint("Directories with index listing enabled : \n$idx");
}else{
    fprint("Directory listing is not enabled");
}
#end Directory List & 404 handling

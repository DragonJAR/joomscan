#start admin finder
dprint("admin finder");

do "$mepath/core/lib.pl";

$amtf=0;
@admins = ('administrator','admin','panel','webadmin','modir','manage','administration',
           'joomla/administrator','joomla/admin','backoffice','cmsadmin','gestion','wp-admin');
foreach $admin(@admins){
    my ($code, $body) = probe_get("$admin/");
    if(($code == 200 and !is_soft404($body, $code)) or $code == 403 or $code == 500 or $code == 501){
        $amtf=1;
        $adming=$admin;
        last;
    }
}

if($amtf==1){
    tprint("Admin page : $target/$adming/");
    # Protection plugins (jSecure etc.) only reveal the panel to clients
    # holding a specific cookie - detect their footprint passively.
    my $res = $ua->get("$target/$adming/");
    my $hdr = $res->headers_as_string;
    if($hdr =~ /jsecure|adminexile|ksecure/i){
        tprint("Protection plugin footprint detected in response headers ($&) - the real admin panel may be hidden");
    }
    # Frontend login: admins can log in via com_users if not blocked
    my ($lcode, $lbody) = probe_get("index.php?option=com_users&view=login");
    if($lcode == 200 and !is_soft404($lbody, $lcode) and $lbody =~ /com_users/i){
        tprint("Frontend login available (admins may authenticate from the frontend) : $target/index.php?option=com_users&view=login");
    }
}else{
    fprint("Admin page not found");
}

#end admin finder

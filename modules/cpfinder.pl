dprint("admin finder");

do "$mepath/core/lib.pl";

$amtf=0;
@admins = ('administrator','admin','panel','webadmin','modir','manage','administration',
           'joomla/administrator','joomla/admin','backoffice','cmsadmin','gestion','wp-admin');
foreach $admin(@admins){
    my ($code, $body) = probe_get("$admin/");
    if (($code == 200 and !is_soft404($body, $code) and is_admin_login($body)) or $code == 403) {
        $amtf = 1;
        $adming = "$target/$admin/";
        last;
    }
}

if (!$amtf) {
    my $root = get_root_url($target);
    if ($root ne "" && $root ne $target && "$root/" ne $target) {
        my ($rcode, $rbody) = probe_get("$root/administrator/");
        if (($rcode == 200 and !is_soft404($rbody, $rcode) and is_admin_login($rbody)) or $rcode == 403) {
            $amtf = 1;
            $adming = "$root/administrator/";
        }
    }
}

if($amtf==1){
    tprint("Admin page : $adming");
    my $res = $ua->get("$adming");
    my $hdr = $res->headers_as_string;
    if($hdr =~ /jsecure|adminexile|ksecure/i){
        tprint("Protection plugin footprint detected in response headers ($&) - the real admin panel may be hidden");
    }
    my ($lcode, $lbody) = probe_get("index.php?option=com_users&view=login");
    if($lcode == 200 and !is_soft404($lbody, $lcode) and $lbody =~ /com_users/i){
        tprint("Frontend login available (admins may authenticate from the frontend) : $target/index.php?option=com_users&view=login");
    }
}else{
    fprint("Admin page not found");
}

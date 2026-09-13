dprint("Checking sensitive config.php.x file");

do "$mepath/core/lib.pl";

my @configs = ('configuration.php_old','configuration.php_new','configuration.php~','configuration.php.new','configuration.php.new~','configuration.php.old','configuration.php.old~','configuration.bak','configuration.php.bak','configuration.php.bkp','configuration.txt','configuration.php.txt','configuration - Copy.php','configuration.php.swo','configuration.php_bak','configuration.php#','configuration.orig','configuration.php.save','configuration.php.original','configuration.php.swp','configuration.save','.configuration.php.swp','configuration.php1','configuration.php2','configuration.php3','configuration.php4','configuration.php6','configuration.php7','configuration.phtml','configuration.php-dist');

my $cnftmp="";
my $ctf=0;
foreach $config(@configs){
    my ($code, $body) = probe_get($config);
    next unless $code == 200;
    next if is_soft404($body, $code);
    if(looks_like_config_leak($body)){
        $cnftmp="$cnftmp\nReadable config file is found \n config file path : $target/$config\n";
        $ctf=1;

        my %flags = (
            'debug'            => qr/public\s+\$debug\s*=\s*'?([^'";]+)'?/i,
            'error_reporting'  => qr/public\s+\$error_reporting\s*=\s*'?([^'";]+)'?/i,
            'force_ssl'        => qr/public\s+\$force_ssl\s*=\s*'?([^'";]+)'?/i,
            'session_handler'  => qr/public\s+\$session_handler\s*=\s*'?([^'";]+)'?/i,
        );
        foreach my $flag (sort keys %flags){
            if($body =~ $flags{$flag}){
                my $val = $1; $val =~ s/\s+//g;
                $cnftmp .= "  $flag = $val\n";
                if($flag eq 'debug' and $val ne '0'){
                    $cnftmp .= "  [!!] Debug mode appears enabled in production - exposes stack traces and data\n";
                }elsif($flag eq 'error_reporting' and $val =~ /maximum|development|all/i){
                    $cnftmp .= "  [!!] error_reporting set to '$val' - full path/stack disclosure risk\n";
                }elsif($flag eq 'force_ssl' and $val eq '0'){
                    $cnftmp .= "  [!!] force_ssl disabled - password/username reset links may downgrade to HTTP (CVE-2026-48902)\n";
                }elsif($flag eq 'session_handler' and $val !~ /database/i){
                    $cnftmp .= "  [*] session_handler is '$val' - database handler recommended\n";
                }
            }
        }
    }
}
if($ctf==0){
    fprint("Readable config files are not found");
}else{
    tprint($cnftmp);
}

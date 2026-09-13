#start sensitive files / VCS metadata finder
# Data-driven: the probe list is declarative; the engine (lib.pl helpers) is shared.
dprint("Finding sensitive files and source-control metadata");

do "$mepath/core/lib.pl";

my @sens_files = (
    'configuration.php.bak',
    'configuration.php~',
    'configuration.php.new',
    'configuration.php.old',
    'configuration.php.orig',
    'configuration.php.save',
    'configuration.php.swp',
    '.configuration.php.swp',
    '.env',
    '.env.backup',
    '.env.bak',
    '.git/config',
    '.git/HEAD',
    '.hg/hgrc',
    '.svn/entries',
    '.DS_Store',
    'backups/',
    'backup/',
    'administrator/backups/',
    'administrator/components/com_akeeba/backup/',
    'administrator/logs/akeeba.backend.log',
    'kickstart.php',
    'logs/',
    'log/',
    'tmp/',
    'cache/',
    'installation/',
    'administrator/errox_banned_agents_logger.log',
    'administrator/cache/',
    'administrator/logs/',
);

my $fnd="";
foreach my $sf (@sens_files){
    my ($code, $body) = probe_get($sf);
    next unless $code == 200;
    next if is_soft404($body, $code);

    my $note = "";
    if($sf =~ /\.git\/config/ and $body =~ /\[(remote|core|user)\]/i){
        $note = " - possible Git repository exposure";
    }elsif($sf =~ /\.env/ and $body =~ /=/){
        $note = " - possible environment variable leak";
    }elsif($sf =~ /configuration\.php|\.bak|\.swp|\.orig|\.save|\.old/ and $body =~ /(dbtype|dbprefix|\$host|\$user|\$password|ftp_pass)/i){
        $note = " - possible configuration backup leak";
    }elsif($sf =~ /installation\// and $body =~ /install|configuration|joomla/i){
        $note = " - installer may still be present";
    }elsif($sf =~ /akeeba/ and $body =~ /(backup|kickstart|akeeba)/i){
        $note = " - Akeeba backup artifact may be exposed";
    }elsif($sf =~ /\/$/){
        # Generic directory probe: require actual directory listing or leak evidence to report
        next unless ($body =~ /<title>Index of/i or $body =~ /Last modified<\/a>/i or $body =~ /Parent Directory<\/a>/i);
        $note = " - directory listing is enabled";
    }
    $fnd .= "Path : $target/$sf\n$note\n" if $note;
    $fnd .= "Path : $target/$sf\n" if !$note;
}
if($fnd){
    tprint("Sensitive files and / or VCS metadata found\n$fnd");
}else{
    fprint("Sensitive files are not found");
}
#end sensitive files finder

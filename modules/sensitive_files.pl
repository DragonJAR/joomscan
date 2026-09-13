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

my $fnd = "";
foreach my $sf (@sens_files){
    my ($code, $body) = probe_get($sf);
    next unless $code == 200;
    next if is_soft404($body, $code);

    my ($ok, $note) = verify_sensitive_file($sf, $code, $body);
    next unless $ok;
    $fnd .= "Path : $target/$sf\n$note\n";
}
if($fnd){
    tprint("Sensitive files and / or VCS metadata found\n$fnd");
}else{
    fprint("Sensitive files are not found");
}

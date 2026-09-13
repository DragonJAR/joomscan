@plinks = ("mambo/mambots/editors/mostlyce/jscripts/tiny_mce/plugins/spellchecker/classes/PSpellShell.php","components/com_docman/dl2.php?archive=0&file=","libraries/joomla/utilities/compat/php50x.php","libraries/joomla/client/ldap.php","libraries/joomla/html/html/content.php","libraries/phpmailer/language/phpmailer.lang-joomla.php","libraries/phpxmlrpc/xmlrpcs.php","index.php?option=com_jotloader&section[]=",'plugins/content/clicktocall/clicktocall.php','/index.php?option=com_remository&Itemid=53&func=[]select&id=5');
foreach $plink(@plinks){
    $source=$ua->get("$target/$plink")->decoded_content;
    if($source =~ m/Cannot modify header information/i || $source =~ m/trim()/i || $source =~ m/header already sent/i || $source =~ m/Fatal error/i || $source =~ m/errno/i || $source =~ m/Warning: /i){
        $pathdis="";
        my @patterns = (
            qr/array given in (.*?) on line/i,
            qr/occurred in (.*?) (?:on|in) line/i,
            qr/on a non-object in (.*?) (?:on|in) line/i,
            qr/No such file or directory.*?in (.*?) (?:on|in) line/i,
            qr/not found in (.*?) (?:on|in) line/i,
        );
        foreach my $pat (@patterns){
            if($source =~ $pat){
                $pathdis = $1;
                last;
            }
        }
   
        $pathdis =~ s/<\/?b>//gi;
        $pathdis =~ s/<\/?strong>//gi;
        dprint("Full Path Disclosure (FPD)");
        tprint("Full Path Disclosure (FPD) in '$target/$plink' : $pathdis\n");
        last;
    }
}
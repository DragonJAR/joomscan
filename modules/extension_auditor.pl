#start extension sensitive endpoint auditor
# Data-driven (DRY): probes come from exploit/db/extension_endpoints.txt and
# only run for components already detected on the target (@found_components),
# so we never waste requests on absent extensions. Non-destructive probes only.
dprint("Auditing sensitive endpoints of detected extensions");

do "$mepath/core/lib.pl";

my $audit_db = "$mepath/exploit/db/extension_endpoints.txt";
my $found = 0;
my $report = "";

if(!@found_components){
    fprint("No detected extensions to audit sensitive endpoints for");
}else{
    if(open(my $EF, "<:encoding(UTF-8)", $audit_db)){
        while(my $row = <$EF>){
            chomp $row;
            next if $row =~ /^\s*$/;
            next if $row =~ /^\s*#/;
            my ($comp, $path, $note) = split /\|/, $row, 3;
            next unless defined $comp && defined $path;
            $comp = lc($comp);
            next unless grep { $_ eq $comp } map { lc($_) } @found_components;
            my ($code, $body) = probe_get($path);
            next unless $code == 200;
            next if is_soft404($body, $code);
            $found = 1;
            my $label = $note;
            $label = "sensitive resource" unless defined $label && $label ne "";
            $report .= "$comp : $target/$path ($label)\n";
        }
        close $EF;
    }

    if($found){
        tprint("Sensitive extension endpoints found / reachable\n$report");
    }else{
        fprint("No sensitive extension endpoints were reachable for detected extensions (" . join(", ", @found_components) . ")");
    }
}
#end extension auditor

#start passive extension discovery (DOM leaks)
# Passively discovers active components referenced in frontend assets.
# Detected components populate @found_components for targeted auditing.
dprint("Discovery of components by passive DOM leak");

do "$mepath/core/lib.pl";

our @found_components = ();

# Fetch the homepage ourselves — relying on $source from ver.pl is fragile
# because ver.pl overwrites $source with manifest/README bodies in fallback chains.
my ($hcode, $dom) = probe_get("");
$dom = "" unless defined $dom;
my %seen = ();
while($dom =~ m{/components/(com_[a-z0-9_]+)/}gi){
    push @found_components, lc($1) unless $seen{lc($1)}++;
}
while($dom =~ m{/media/(com_[a-z0-9_]+)/}gi){
    push @found_components, lc($1) unless $seen{lc($1)}++;
}
if(@found_components){
    tprint("Components discovered in frontend assets : " . join(", ", @found_components));
}else{
    fprint("No component assets found in the frontend HTML");
}
#end passive extension discovery

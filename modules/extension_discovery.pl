dprint("Discovery of components by passive DOM leak");

do "$mepath/core/lib.pl";

our @found_components = ();

my ($hcode, $dom) = probe_get("");
$dom = "" unless defined $dom;
my %seen = ();
while($dom =~ m{/components/(com_[a-z0-9_]+)/}gi){
    push @found_components, lc($1) unless $seen{lc($1)}++;
}
while($dom =~ m{/media/(com_[a-z0-9_]+)/}gi){
    push @found_components, lc($1) unless $seen{lc($1)}++;
}
while($dom =~ m{/(?:components|media)/(com_[a-z0-9_]+)/[^"'>]*[?&]v(?:ersion)?=?([0-9]+(?:\.[0-9]+)+)}gi){
    my $c = lc($1);
    my $v = $2;
    $component_versions{$c} = $v unless exists $component_versions{$c};
}
if(@found_components){
    tprint("Components discovered in frontend assets : " . join(", ", @found_components));
}else{
    fprint("No component assets found in the frontend HTML");
}

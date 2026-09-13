use strict;
use warnings;
use Test::More tests => 9;

ok(-f "exploit/db/componentslist.txt", "componentslist.txt exists");
open(my $cfh, "<:encoding(UTF-8)", "exploit/db/componentslist.txt") or die $!;
my @comps = <$cfh>;
close $cfh;
cmp_ok(scalar(@comps), ">=", 1000, "componentslist.txt contains at least 1000 entries");

ok(-f "exploit/db/corevul.txt", "corevul.txt exists");
open(my $cvfh, "<:encoding(UTF-8)", "exploit/db/corevul.txt") or die $!;
my $core_count = 0;
my $core_errs = 0;
while(my $line = <$cvfh>){
    chomp $line;
    next if $line =~ /^\s*$/;
    $core_count++;
    my ($v, $d) = split /\|/, $line, 2;
    $core_errs++ unless defined $d;
}
close $cvfh;
cmp_ok($core_count, ">=", 200, "corevul.txt has over 200 advisories");
is($core_errs, 0, "corevul.txt has zero malformed lines");

ok(-f "exploit/db/comvul.txt", "comvul.txt exists");
open(my $vfh, "<:encoding(UTF-8)", "exploit/db/comvul.txt") or die $!;
my $comvul_count = 0;
while(my $line = <$vfh>){
    chomp $line;
    my @m = ($line =~ /\[(.*?)\]/g);
    $comvul_count++ if @m >= 7;
}
close $vfh;
cmp_ok($comvul_count, ">=", 1000, "comvul.txt has over 1000 component exploit entries");

ok(-f "exploit/db/extension_endpoints.txt", "extension_endpoints.txt exists");
open(my $efh, "<:encoding(UTF-8)", "exploit/db/extension_endpoints.txt") or die $!;
my $endpoint_count = 0;
while(my $line = <$efh>){
    chomp $line;
    next if $line =~ /^\s*$/;
    my ($c, $p, $n) = split /\|/, $line, 3;
    $endpoint_count++ if defined $c && defined $p;
}
close $efh;
cmp_ok($endpoint_count, ">=", 30, "extension_endpoints.txt has declarative endpoints");

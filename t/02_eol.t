use strict;
use warnings;
use Test::More tests => 13;

our $mepath = ".";
require "./core/lib.pl";

my $s1 = eol_series_for("1.5.26");
ok(defined $s1, "Series 1 found");
is($s1->[0], 1, "Series 1 major is 1");

my $s4 = eol_series_for("4.4.14");
ok(defined $s4, "Series 4 found");
is($s4->[0], 4, "Series 4 major is 4");

my $s6 = eol_series_for("6.0.0");
ok(defined $s6, "Series 6 found");
is($s6->[0], 6, "Series 6 major is 6");

is(eol_series_for("99.0.0"), undef, "Unknown series returns undef");

is(jsupport_status("1.5.26"), "eol", "Joomla 1.5.26 is EOL");
is(jsupport_status("2.5.28"), "eol", "Joomla 2.5.28 is EOL");
is(jsupport_status("3.10.12"), "eol", "Joomla 3.10.12 is EOL");
is(jsupport_status("5.4.8"), "active", "Joomla 5.4.8 is actively supported");
is(jsupport_status("6.1.3"), "active", "Joomla 6.1.3 is actively supported");
is(eol_series_for("6.1.3")->[2], "6.1.3", "Series 6 includes 6.1.3 release");

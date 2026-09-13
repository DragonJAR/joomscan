use strict;
use warnings;
use Test::More tests => 7;

my $help_out = `perl joomscan.pl --help 2>&1`;
is($?, 0, "CLI --help exits with 0");
like($help_out, qr/Usage:\s+joomscan\.pl/i, "CLI --help contains usage banner");
like($help_out, qr/--threads/i, "CLI --help lists --threads option");
like($help_out, qr/--delay/i, "CLI --help lists --delay option");

my $ver_out = `perl joomscan.pl --version 2>&1`;
is($?, 0, "CLI --version exits with 0");
like($ver_out, qr/Version\s+:\s+\d+\.\d+\.\d+/i, "CLI --version outputs version string");

my $empty_out = `perl joomscan.pl 2>&1`;
isnt($?, 0, "CLI without target exits with non-zero code");

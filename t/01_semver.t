use strict;
use warnings;
use Test::More tests => 22;

our $mepath = ".";
require "./core/lib.pl";

is(vers_cmp("3.9.1", "3.9.1"), 0, "Equal versions return 0");
is(vers_cmp("3.9.0", "3.9.1"), -1, "Lower version returns -1");
is(vers_cmp("3.9.2", "3.9.1"), 1, "Higher version returns 1");
is(vers_cmp("4.0.0", "3.10.12"), 1, "Major version change returns 1");
is(vers_cmp("1.0", "1.0.0"), 0, "Trailing zeroes in comparison");
is(vers_cmp("1.0.1", "1.0"), 1, "Short string comparison");
is(vers_cmp("0.9.4.1", "0.9.4"), 1, "Sub-patch comparison");
is(vers_cmp("5.0.0", "5.0.0-rc1"), 0, "RC stripped cleanly to numeric parts");

is(version_in_range("4.2.5", "4.0.0", "4.2.7"), 1, "Version in closed range");
is(version_in_range("4.0.0", "4.0.0", "4.2.7"), 1, "Version at lower bound");
is(version_in_range("4.2.7", "4.0.0", "4.2.7"), 1, "Version at upper bound");
is(version_in_range("4.2.8", "4.0.0", "4.2.7"), "", "Version above upper bound");
is(version_in_range("3.9.9", "4.0.0", "4.2.7"), "", "Version below lower bound");
is(version_in_range("5.1.0", "5.0.0", ""), 1, "Unbounded upper range");
is(version_in_range("2.5.0", "", "3.0.0"), 1, "Unbounded lower range");
is(version_in_range("invalid", "1.0.0", "2.0.0"), "", "Non-numeric version returns empty");

is(joomla_version_num("Joomla 4.2.8"), "4.2.8", "Parse standard version string");
is(joomla_version_num("Joomla! 3.10.12-Stable"), "3.10.12", "Parse version with prefix and suffix");
is(joomla_version_num("5.0.3"), "5.0.3", "Parse pure version number");
is(joomla_version_num("1.0.15.1"), "1.0.15.1", "Parse 4-part version number");
is(joomla_version_num("Joomla unknown"), "", "Unknown version returns empty");
is(joomla_version_num(undef), "", "Undefined version returns empty");

use strict;
use warnings;
use Test::More tests => 6;

our $mepath = ".";
our $threads = 4;
require "./core/lib.pl";

my @items = (1..20);

my $seq_res = run_pool(\@items, sub {
    my $x = shift;
    return $x * 2;
}, 1);
is(scalar(@$seq_res), 20, "run_pool sequential processes all items");
is($seq_res->[0], 2, "sequential item calculation correct");

my $par_res = run_pool(\@items, sub {
    my $x = shift;
    return $x * 2;
}, 4);
is(scalar(@$par_res), 20, "run_pool parallel processes all items");
my @sorted_par = sort { $a <=> $b } @$par_res;
is_deeply(\@sorted_par, [map { $_ * 2 } 1..20], "parallel pool yields identical elements");

my $empty_res = run_pool([], sub { shift }, 4);
is_deeply($empty_res, [], "run_pool on empty array returns empty list");

my $undef_res = run_pool(\@items, sub {
    my $x = shift;
    return $x % 2 == 0 ? $x : undef;
}, 3);
my @evens = sort { $a <=> $b } @$undef_res;
is_deeply(\@evens, [2, 4, 6, 8, 10, 12, 14, 16, 18, 20], "run_pool correctly skips undef worker returns");

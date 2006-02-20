# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Symantec-PCAnywhere-Profile-CHF.t'

#########################

use strict;
use warnings;
use Test::More tests => 2;
#
# Test 1 ensures we have the module to begin with
#
BEGIN { use_ok('Symantec::PCAnywhere::Profile::CHF') };

###
# Main tests start here
###

# TODO: Test more/all fields
my %pairs = (
	AreaCode	=> 800,
	ControlPort	=> 9989,
	PhoneNumber	=> 5551234,
	IPAddress	=> '127.0.0.9',
);
my @chf;
$chf[0] = new Symantec::PCAnywhere::Profile::CHF;
$chf[0]->set_attrs(%pairs);
my $data = $chf[0]->encode;

$chf[1] = new Symantec::PCAnywhere::Profile::CHF(-data => $data);
my $results = $chf[1]->get_attrs(keys %pairs);

#
# Test 2 checks whether parsing a fresh file gives sane output
#
is_deeply($results, \%pairs, 'Parse new file');


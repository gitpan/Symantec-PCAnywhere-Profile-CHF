# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Symantec-PCAnywhere-Profile-CHF.t'

#########################

use Test::More tests => 1;
BEGIN { use_ok('Symantec::PCAnywhere::Profile::CHF') };

#########################

my $chf = new Symantec::PCAnywhere::Profile::CHF;
$chf->set_attrs(
	PhoneNumber	=> 1234,
	AreaCode	=> 715,
	IPAddress	=> '10.10.128.99',
	ControlPort	=> '5900'
);
print $chf->encode;

my $chf = new Symantec::PCAnywhere::Profile::CHF(shift);
use Data::Dumper;
my %results = $chf->get_attrs(
	ConnectionName,
	PhoneNumber,
	AreaCode,
	IPAddress,
	ControlPort
);
while (my ($attr, $value) = each (%results)) {
	print "$attr\t= $value\n";
}
my $chf = new pcAnywhere::Util::CHF('test.chf');
print "$_\n" for sort $chf->get_fields;

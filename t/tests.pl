#!/usr/bin/perl
use lib ".";
use Symantec::PCAnywhere::Profile::CHF;

my $chf = new Symantec::PCAnywhere::Profile::CHF;
$chf->set_attrs(
	PhoneNumber	=> 1234,
	AreaCode	=> 715,
	IPAddress	=> '10.10.128.99',
	ControlPort	=> '5900'
);
print $chf->encode;

#!/usr/bin/perl
use lib ".";
use Symantec::PCAnywhere::Profile::CHF;

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
#!/usr/bin/perl
use lib ".";
use Symantec::PCAnywhere::Profile::CHF;

my $chf = new pcAnywhere::Util::CHF('test.chf');
print "$_\n" for sort $chf->get_fields;

# 
# This module is based on 'pcainfo' from Stephen J. Friedl. His work,
# which is in the public domain, has been modified to add encoding
# capabilities to allow creating CHFs (pcAnywhere connection profiles).
# His contact information is below. Thanks, Stephen!
# 
# Stephen J. Friedl
# Software Consultant
# Tustin, California USA
# steve@unixwiz.net / www.unixwiz.net
# 2002/02/26
# 
# The addition of encoding and an OO interface, as well as the packag-
# ing as a CPAN module and the correcting of some typographical errors,
# semantic redundancies, and spelling mistakes, was done by Darren Kulp.
# 
# Darren Kulp
# Computer Science Undergraduate Student
# University of Wisconsin - Eau Claire
# Eau Claire, Wisconsin USA
# kulp@thekulp.com / www.thekulp.com
# 2006-02-15
# 
package Symantec::PCAnywhere::Profile::CHF;

use strict;
use warnings;
our $VERSION = '0.01';

use base qw(Symantec::PCAnywhere::Profile);
use Compress::Zlib;
use MIME::Base64;

# Compressed and encoded template CHF
my $chf_template = uncompress(decode_base64(<<'TEMPLATE'));
eJz7t4qB4Q0PAwMjEBpwMzA45STmZTOAgYJzYk4OwygYBaNgRADGgXYAkQDsTq6BdsUooBPg5Q5x
DtD3DKDACKSUzczAxAgElDpqFIyCUTAKhhL4P9AOGGAAAOhdCT4=
TEMPLATE

my %FIELDS_CHF = (
	#                      off  len type
	#                     ----  --- ----
	ConnectionName   => [   16, 182, 0 ],
	FilePassword     => [  280, 128, 0 ],
	SaveSessionFile  => [  744, 128, 0 ],
	ScriptFileName   => [  889, 128, 0 ],
	PhoneNumber      => [ 1038,  31, 0 ],
	Location         => [ 1069, 128, 0 ],
	AreaCode         => [ 1210,  40, 0 ],
	IPAddress        => [ 1324, 128, 0 ],
	ConxType         => [ 1701,  64, 0 ],
	ConnCount        => [ 1913,   1, 2 ],
	RetrySecs        => [ 1914,   1, 2 ],
	Gateway          => [ 1928,  24, 0 ],
	Hostname         => [ 1940, 128, 0 ],
	Domain_Logname   => [ 2093, 128, 0 ],
	Password         => [ 2222, 128, 0 ],
	# TODO: Find what is missing between these
	DenyLowerEncr    => [ 3050,   1, 2 ],
	EncrLevel        => [ 3052,   1, 2 ],
	PrivKeyContainer => [ 3053,  48, 0 ],
	CertCommonName   => [ 3103,  48, 0 ],
	DataPort         => [ 3154,   2, 3 ],
	ControlPort      => [ 3156,   2, 3 ],
);

sub new {
	my $type = shift;
	my %defaults = (
		fields		=> \%FIELDS_CHF,
		template	=> $chf_template,
	);

	my $self = $type->SUPER::new(%defaults, @_);
	return $self;
}

###
# Private methods below
###

#
# decode_pca_file
#
#	Provided with XOR-encoded CHF data, un-obscure the whole
#	thing into the "clear" format. The return value is the same
#	length as the input string, but after XOR decoding.
#

sub decode_pca_file ($$) {
	my $self = shift;
	my $rawdata = $self->{data};

	my $part1 = substr($rawdata, 0, 444);
	my $part2 = substr($rawdata, 444);

	return $self->rawdecode(255, 0,    $part1)
	     . $self->rawdecode(255, 0x54, $part2);

}

#
# encode_pca_file
#
#	Provided with XOR-unencoded CHF data, obscure the whole
#	thing into the "encrypted" format. The return value is the
#	same length as the input string, but after XOR encoding.
#

sub encode_pca_file ($$) {
	my $self = shift;
	my $rawdata = $self->{decoded};

	my $part1 = substr($rawdata, 0, 444);
	my $part2 = substr($rawdata, 444);

	return $self->rawencode(255, 0,    $part1)
	     . $self->rawencode(255, 0x54, $part2);
}

1;
__END__
# Documentation follows

=head1 NAME

Symantec::PCAnywhere::Profile::CHF - Encodes and decodes Symantec pcAnywhere connection
profiles

=head1 SYNOPSIS

	use Symantec::PCAnywhere::Profile::CHF;
	
	# Load CHF file from file
	my $chf = new Symantec::PCAnywhere::Profile::CHF(filename => $filename);
	
	# Load CHF data directly
	my $chf = new Symantec::PCAnywhere::Profile::CHF(data => $data);
	
	my $results = $chf->get_attrs(
		Location,
		Password,
		Hostname,
		DataPort
	);
	while (my ($attr, $value) = each (%$results)) {
		print "$attr\t= $value\n";
	}
	
	# Create an empty CHF
	my $chf = new Symantec::PCAnywhere::Profile::CHF;
	$chf->set_attrs(
		PhoneNumber	=> 7652314,
		AreaCode	=> 999,
		IPAddress	=> '10.10.128.99',
		ControlPort	=> 5900
	);
	
	# Print the binary CHF file
	print $chf->encode;


=head1 DESCRIPTION

This module is responsible for decoding of a pcAnywhere .CHF file
that describes a remote system the client wishes to connect to.
CHF files seem to always be the same size (3308 bytes), which is helpful
for decoding.

See this module's base class for more information on the decoding
mechanism.

=head2 EXPORT

None.

=head1 METHODS

Here is the public API; see this module's base class documentation for more
information on the inner workings of the encoding and decoding process, as well
as additional useful methods.

=head2 new

	my $chf = new Symantec::PCAnywhere::Profile::CHF;
	my $chf = new Symantec::PCAnywhere::Profile::CHF(-filename => $filename);
	my $chf = new Symantec::PCAnywhere::Profile::CHF(filename => $filename);
	my $chf = new Symantec::PCAnywhere::Profile::CHF(-data => $chfdata);
	my $chf = new Symantec::PCAnywhere::Profile::CHF(data => $chfdata);

The "new" constructor takes any number of arguments and sets the appropriate
flags internally before returning a new object. The arguments are considered as
a list of key-value pairs which are inserted into the object data.

=head2 decode

	$chf->decode;
	$chf->decode($chfdata);

Decodes the currently-loaded data or new data passed in.

=head2 encode

	$chf->encode;

Returns an encoded representation of the CHF file, constructed from the
attributes previously set by set_attrs or existing from a constructor or
load_from_file() call.

=head1 SEE ALSO

This module is based very heavily on the work of Stephen Friedl at
http://www.unixwiz.net/tools/pcainfo.htmlZ<>.

=head1 TO DO

Very early in the file is a "description" field that we are not
quite decoding properly.

The "hostname" and "IP Address" fields seem to be redundant,
and this requires more research.

There are still plenty of big unused fields in the .CHF file,
and we ought to find out what they are used for. Try looking
at the other protocols (ISDN, SPX, NETBIOS, etc.)

Based on http://www.cpan.org/modules/00modlist.long.html#ID2_GuidelinesfZ<>,
refactor code to pass references to lists instead of lists.

=head1 BUGS / CAVEATS

They're in there somewhere. Let me know what you find.

=head1 AUTHOR

Darren Kulp, E<lt>kulp@thekulp.comE<gt>, based on code from
Stephen J. Friedl, (http://unixwiz.net/)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Darren Kulp

Contains code placed in the public domain 2002 by Stephen Friedl

"Symantec" and "pcAnywhere" are trademarks of Symantec Corp.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

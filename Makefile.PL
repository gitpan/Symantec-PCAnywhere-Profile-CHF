use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Symantec::PCAnywhere::Profile::CHF',
    VERSION_FROM      => 'lib/Symantec/PCAnywhere/Profile/CHF.pm', # finds $VERSION
    PREREQ_PM         => {
	'Symantec::PCAnywhere::Profile' => 0,
    	'Compress::Zlib' => 0,
	'MIME::Base64' => 0,
	'Carp' => 0,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Symantec/PCAnywhere/Profile/CHF.pm', # retrieve abstract from module
       AUTHOR         => 'Darren Kulp <kulp@thekulp.com>') : ()),
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
);

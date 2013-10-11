use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Flowd',
    VERSION_FROM      => 'lib/Flowd.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Flowd.pm', # retrieve abstract from module
       AUTHOR         => 'Damien Miller <djm@mindrot.org>') : ()),
    LIBS              => ['-L.. -lflowd'], # e.g., '-lm'
#    DEFINE            => '-DHAVE_CONFIG_H', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I. -I..', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);

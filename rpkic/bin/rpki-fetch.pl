#!/usr/bin/perl
#
# (setq cperl-indent-level 8)
# (setq perl-indent-level 8)
#
use strict;
use warnings;

use Pod::Usage;
use Getopt::Long qw(:config posix_default);
use Config::Simple;
use Data::Dumper;
use File::Basename;
use File::Path;

=head1 NAME

rpki-fetch.pl

=head1 SYNOPSIS

    rpki-fetch.pl [OPTIONS] 

=head2 OPTIONS

=over 8

=item --config|-c I<filename>

Load the configuration file I<filename>, the default is I<./rfetch.cfg>

=item --verbose|-v

Enables verbose output.

=item --output|-o I<filename>

Write the configuration file I<filename> that will be used as input for
rpki-validate.pl. The default is I<./rvalid.cfg>

=back

=head1 OVERVIEW

rpki-fetch uses rysnc to fetch the RPKI certificate repositories stored in the
configuration file. Look to the CONFIGURATION FILE section to understand the
format and options available.


=head1 CONFIGURATION FILE

The configuration file (I<./rfetch.cfg> by default) is processed by
C<Config::Simple> using the B<INI-FILE> format. For more clarification use
I<perldoc Config::Simple>.

Configuration files permit comments, started with a hash sign C<#> or semi-colon
C<;>. Comments should reside on their own lines.

A configuration file has two types of blocks. The first type are reserved names,
such as C<rpki>. The second type is a repository block, identified by a preceding
C<repo:>, such as C<repo:apnic>. There are an unlimited number of repository
blocks and are provided by the user.

Each of the L<CONFIGURATION PARAMETERS> are assign a value with an equals C<=>
sign. 

=head2 CONFIGURATION PARAMATERS

=head2 CONFIGURATION FILE EXAMPLE
    
    # The global rpki block
    [rpki]
    # The root directory to hold the cache data
    root_dir=/var/rpki/
    output_cfg=./rvalid.cfg

    # A block for the apnic repositories
    [repo:apnic]
    1:uri=rsync://rpki.apnic.net/member_repository
    2:uri=rsync://rpki.apnic.net/repository

    # And another for lacnic
    [repo:lacnic]
    1:uri=rsync://repository.lacnet.net/rpki

=cut


# 
# False entry point to give perl some structure
#
# Returns:
#     0 upon sucess
#     1 upon failure
#
sub main {
	my (%opts, $ok);

	$ok = parse_args(\%opts);
	if (!$ok) {
		return 1;
	}

	vprintf("Using configuration file: %s\n", $opts{'config-file'});
	my %config = read_config(file => $opts{'config-file'});
	if (!%config) {
		return 1;
	}

	# Output stuff.
	my $csimple = new Config::Simple(syntax => 'ini');
	$csimple->param("rpki.output-dir", "rpki-cache");
	
	my @kids;
	foreach my $key (sort keys %config) {
		vprintf("Key: %s\n", $key);
		if ($key =~ /repo:(.*)\.(\d+):uri/) {
			# There's an rsync repository here we hope.
			my $cfg_key = "ta:$1.$2:";
			vprintf("     %s=%s\n", $cfg_key."base-uri", $config{$key});
			$csimple->param($cfg_key."base-uri", $config{$key});

			my $basename = join ('/', $config{'rpki.root_dir'}, $1,
					     basename($config{$key}));

			vprintf("     %s=%s\n", $cfg_key."repo-dir", $basename);
			$csimple->param($cfg_key."repo-dir", $basename);
			vprintf("     directory=%s\n", dirname($basename));

			# Might as well do it here... Get it out of the way.
			my $pid = fork();
			if ($pid == 0) {
				# child, begin rsync
				File::Path::make_path(dirname($basename));
				my $cmd = "rsync --progress --append-verify -vrz ";
				$cmd .= $config{$key} . " " . $basename;
				vprintf("$cmd\n");
				system($cmd);
				exit(0);
			} else {
				push(@kids, $pid);
			}
		}
	}
	for (@kids) {
		waitpid($_, 0);
	}

	$csimple->write($config{'rpki.output_cfg'});

	return 0;
}

#
# Parses the command line arguments
#
# Usage:
#     parse_args(\%opts);
#
# Returns:
#     undef when the program should exit.
#     true when the program arguments have been satisfied.
#
# Side Effects:
# %opts = (
#     config-file => #path to config file, guaranteed.
#     verbose => #true when set, undef otherwise.
#     usage => #true when set, undef otherwise.
#     output => #path to the output configuration file, guaranteed.
# )
#
sub parse_args {
	my ($opts, $ok);
	($opts) = @_;

	$opts->{'config-file'} = "./rfetch.cfg";

	$ok = GetOptions("config-file|s" => \$opts->{'config-file'},
			 "verbose|s" => \&enable_verbose,
			 "usage" => \$opts->{'usage'},
			);

	if ($opts->{'usage'}) {
		pod2usage(-noperldoc => 1);
		return undef;
	}

	if (!$ok) {
		return undef;
	}

	return 1;
}

#
# Reads the configuration file.
#
# Usage:
#     %config = read_config(file => <filename>);
#
# Returns:
#     The configuration hash upon success, undef otherwise.
#
sub read_config {
	my %args = @_;
	my %config;

	my $ok = Config::Simple->import_from($args{'file'}, \%config);
	if (!$ok) {
		eprintf(Config::Simple->error() . "\n");
		return ();
	}

	if (!defined($config{'rpki.output_cfg'})) {
		eprintf($args{'file'} . " has no output_cfg set\n");
		return ();
	}

	if (!defined($config{'rpki.root_dir'})) {
		eprintf($args{'file'} . " has no root_dir set\n");
		return ();
	}

	return (%config);
}

#
# Enables verbose messages
#
# Usage:
#     enable_verbose();
#
our $VERBOSE;
sub enable_verbose {
	$VERBOSE = 1;

	vprintf("Verbose output enabled\n");
}

#
# Displays a message when verbosity has been enabled.
#
# Usage:
#     vprintf("This is a message %s", $foo);
#
sub vprintf {
	return unless $VERBOSE;

	printf("VERBOSE: ");
	printf(@_);
}

#
# Displays an error message
#
# Usage:
#     eprintf("This is an error message %s", $foo);
#
sub eprintf {
	printf STDERR ("ERROR: ");
	printf STDERR (@_);
}
	
exit main();

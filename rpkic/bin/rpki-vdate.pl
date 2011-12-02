#!/usr/bin/perl
#
# (cperl-mode)
# (setq cperl-indent-level 8)
# (setq perl-indent-level 8)
#
use strict;
use warnings;

BEGIN {
	use File::Basename;
	my $dir = dirname(__FILE__);
	push @INC, $dir;
}

use Pod::Usage;
use Getopt::Long qw(:config posix_default);
use Config::Simple;
use Data::Dumper;
use File::Path;
use File::Copy;


use TrustAnchor;
use ROA;

=head1 NAME

rpki-fetch.pl

=head1 SYNOPSIS

    rpki-vdate.pl [OPTIONS] 

=head2 OPTIONS

=over 8

=item --config|-c I<filename>

Load the configuration file I<filename>, the default is I<./rvalid.cfg>

=item --verbose|-v

Enables verbose output.

=head1 OVERVIEW

rpki-vdate.pl verifies copies of RPKI trust achor certificates. After
the user has copied the contents of a trust anchor's certificates
rpki-vdate.pl will validate the chain of certificates. Valid
certificates are placed within the C<valid/> subdirectory, invalid
certificates within the C<invalid/> subdirectory.

=head1 CONFIGURATION FILE

=head2 CONFIGURATION PARAMATERS

=item cert-dir

Specifies the root of the output directory for certificates.

=head2 CONFIGURATION FILE EXAMPLE

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
	return 1 unless $ok;

	my (%config);
	$ok = read_cfg(file => $opts{'config-file'}, config => \%config);
	return 1 unless $ok;
	vprintf("Output directory is: %s\n", $config{'rpki.output-dir'});

	for my $name (get_ta_names()) {
		my $ta = get_ta(name => $name);
		$ok = process_ta(ta => $ta,
				 rootdir => $config{'rpki.output-dir'});
		return 1 unless $ok;
	}
	
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

	$opts->{'config-file'} = "./rvalid.cfg";

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
# Continues the current line if verbose is enabled
#
sub vprintc {
	return unless $VERBOSE;

	printf(@_);
}


#
# Displays an error message.
#
# Usage:
#     eprintf("This is an error message %i", $int);
#
sub eprintf {
	printf(STDERR "ERROR: ");
	printf(STDERR @_);
}

#
# Reads the configuration file and stores the information found
# within. 
#
# Usage:
#     $ok = read_cfg(file => $path, 
#                    config => \%config);
#
# Returns:
#     true upon success
#     undef otherwise
#
# Side effects:
#     Error messagse are displayed by calling eprintf()
#
sub read_cfg {
	my (%args);
	(%args) = @_;

	vprintf("Reading configuration file: %s\n", $args{'file'});

	my ($ok, $config);
	$config = $args{'config'};

	$ok = Config::Simple->import_from($args{'file'}, \%{$config});
	if (!$ok) {
		eprintf("Configuration file (%s) error: %s\n", 
			$args{'file'},Config::Simple->error());
		return undef;
	}

	my ($odir);
	$odir = $config->{'rpki.output-dir'};
	if (!defined($odir)) {
		eprintf("Configuration file has no output-dir\n");
		return undef;
	}

	for my $key (keys %{$config}) {
		if ($key =~ /^ta:(.*)\./) {
			$ok = add_ta(name => $1);
			return undef unless $ok;
		} else {
			next;
		}
		my ($ta);
		$ta = get_ta(name => $1);
		if ($key =~ /^ta:(.*)\.(\d+):repo-dir/) {
			# $1 - name
			# $2 - repo instance #
			my $urikey = "ta:$1.$2:base-uri";
			if (!defined($config->{$urikey})) {
				eprintf("%s no base-uri for repository %s\n",
					$ta->getName(),	$config->{$key});
				return undef;
			}
			$ok = $ta->addRepo(dir => $config->{$key},
					   uri => $config->{$urikey});
			if (!$ok) {
				eprintf("%s could not add repository with dir "
					. "%s and uri %s\n",
					$config->{$key}, $config->{$urikey});
				return undef;
			}
		}
	}
	

	return 1;
}	
	
#
# Creates an empty TA entry if needed.
#
# Usage:
#     add_ta(name => $name);
#
# Returns:
#     true upon success
#     undef otherwise
#
our %TAs;
sub add_ta {
	my (%args);
	%args = @_;

	if (!defined($args{'name'})) {
		return undef;
	}

	if (defined($TAs{$args{'name'}})) {
		return 1;
	}

	vprintf("Storing TA $args{name}\n");
	$TAs{$args{'name'}} = new TrustAnchor(name => $args{'name'});
}

#
# Gets a TA
#
# Usage:
#     get_ta(name => $name);
#
# Returns:
#     a TrustAnchor object upon success
#     undef otherwise
#
sub get_ta {
	my %args = @_;

	if (!defined($TAs{$args{'name'}})) {
		return undef;
	}
	return $TAs{$args{'name'}};
}

#
# Gets the names of all the TAs
#
# Usage:
#     @names = get_ta_names();
#
# Returns:
#     The list of TrustAnchor names
#
sub get_ta_names {
	return keys %TAs;
}

#
# Processes a single Trust Anchor
#
# Usage:
#     $ok = process_ta(ta => $ta,
#                      rootdir => $dir);
#
# Returns:
#     true if processing was successful
#     undef if processing failed.
#
# Note:
#     Processing does not fail if a certificate is invalid. Processing fails
#     when some portion of certificate validation cannot be performed.
#
sub process_ta {
	my %args = @_;
	my ($ta, $odir);
	($ta, $odir) = @args{'ta', 'rootdir'};

	if (!defined($ta)) {
		return undef;
	}

	if (!defined($odir)) {
		return undef;
	}

	printf("Processing Trust Anchor: %s\n", $ta->getName());

	my @certs = $ta->getCerts();
	printf("Found [%i] certificates\n", $#certs + 1);
	for my $cert (@certs) {
		my $ok;
		$ok = process_cert(ta => $ta, rootdir => $odir, cert => $cert);
		if (!$ok) {
			eprintf("Could not process cert %s\n",	$cert);
			return undef;
		}
	}

	my @roas = $ta->getROAs();
	printf("Found [%i] ROAs\n", $#roas + 1);
	for my $roa (@roas) {
		my $ok;
		$ok = process_roa(ta => $ta, rootdir => $odir, roa => $roa);
		if (!$ok) {
			eprintf("Could not process ROA %s\n", $roa);
			return undef;
		}
	}
	
	return 1;
}

#
# Processes a single certificate 
#
# Usage:
#     $ok = process_cert(ta => $ta,
#                        rootdir => $dir,
#                        cert => $cert);
#
# Returns:
#     true if processing was successful
#     undef if processing failed
#
sub process_cert {
	my %args = @_;
	my ($ta, $odir, $cert);
	($ta, $odir, $cert) = @args{'ta', 'rootdir', 'cert'};

	printf("Processing cert %s ... ", basename($cert));

	my $pem = inproc_path(%args);

	my ($ok);
	if (! -e $pem) {
		# Need to convert.
		$ok = convert_cert(in => $cert, out => $pem);
		if (!$ok) {
			eprintf("Could not convert %s to %s\n",	$cert, $pem);
			return undef;
		}
	}

	my @cert_chain = cert_chain(ta => $ta, rootdir => $odir, pem => $pem);
	if ($#cert_chain == 0) {
		# The root certificate this will be validated many times during
		# as the other certificates are processed.
		printf("CAFile detected ");
		$ok = 1;
	} else {
		$ok = valid_chain(@cert_chain);
	}

	use File::Copy;
	my $path;
	if ($ok) {
		# valid;
		printf("valid\n", basename($cert));
		$path = valid_path(ta => $ta, rootdir => $odir, cert => $cert);
		File::Path::make_path(dirname($path));
		copy($cert, $path);
		$path =~ s/\.cer/\.pem/;
		copy($pem, $path);
	} else {
		# invalid;
		printf("invalid\n", basename($cert));
		$path = invalid_path(ta => $ta, rootdir => $odir, cert => $cert);
		File::Path::make_path(dirname($path));
		copy($cert, $path);
		$path =~ s/\.cer/\.pem/;
		copy($pem, $path);
	}

	return 1;
}

#
# Finds the 'in process' path for a certificate filename.
#
# $file = inproc_path(ta => $ta, rootdir => $dir, cert => $cer_path);
#
# Returns:
#     the in process file name including the path.
#
sub inproc_path {
	my %args = @_;
	my ($ta, $cert, $odir);
	($ta, $cert, $odir) = @args{'ta', 'cert', 'rootdir'};

	#
	# This is subtle magic. As a goal, this script should not modify the
	# contents of the provided directory. However the ASN.1 encoded
	# certificates cannot be manipulated with the openssl tools.
	#
	# Therefor, the output-dir/$taName/inproc directory will hold the
	# certificates with the same path except renamed to .pem
	#

	my $pem = $odir . '/' . $ta->getName() . '/inproc/' . $cert;
	$pem =~ s/\.cer$/\.pem/;

	return $pem;
}

#
# Finds the 'valid path' for a certificate filename.
#
# Usage:
#     $file = valid_path(ta => $ta, rootdir => $dir, cert => $cer_path);
#
# Returns:
#     the path to the valid file
sub valid_path {
	my %args = @_;
	my ($ta, $cert, $odir);
	($ta, $cert, $odir) = @args{'ta', 'cert', 'rootdir'};

	my $file = $odir . '/' . $ta->getName() . '/valid/' . $cert;
	$cert =~ s/$odir//;
	vprintf("valid_path ODIR: $odir\n");
	vprintf("valid_path TA Name: " . $ta->getName() . "\n");
	vprintf("valid_path Cert: $cert\n");
	vprintf("valid_path: $file\n");

	return $file;
}

#
# Finds the 'invalid path' for a certificate filename.
#
# Usage:
#     $file = invalid_path(ta => $ta, rootdir => $dir, cert => $cer_path);
#
# Returns:
#     the path to the invalid file
sub invalid_path {
	my %args = @_;
	my ($ta, $cert, $odir);
	($ta, $cert, $odir) = @args{'ta', 'cert', 'rootdir'};

	my $file = $odir . '/' . $ta->getName() . '/invalid/' . $cert;

	vprintf("invalid_path: $file\n");
	return $file;
}

#
# Converts an ASN.1 formatted certificate into a PEM formatted one.
# 
# Usage:
#     $ok = covert_cert(in => $infile,
#                       out => $outfile);
#
# Returns:
#     true upon success
#     undef otherwise
#
sub convert_cert {
	my %args = @_;
	my ($in, $out);
	($in, $out) = @args{'in', 'out'};

	vprintf("Converting %s to %s\n", $in, $out);

	File::Path::make_path(dirname($out));
	my @outp = qx/openssl x509 -inform der -outform pem -in $in -out $out 2>&1/;
	if (grep {/error/i} @outp) {
		return undef;
	}

	return 1;
}

#
# Gets all of the certificates in the chain, given the end of the
# chain. When a member of the certificate isn't in the 'inproc'
# directory it is converted and added.
# 
# Usage:
#     @cert_chain = cert_chain(ta => $ta, rootdir => $root,
#         pem =>  $pem);
#
# Returns:
#     The list of certificates in the chain all the way to the root 
#
#
sub cert_chain {
	my %args = @_;
	my ($ta, $pem, $odir);
	($ta, $pem, $odir) = @args{'ta', 'pem', 'rootdir'};

	my @chain = ($pem);
	my $uri = cert_issuer_uri($pem);

	while ($uri) {
		my ($file_name);
		$file_name = $ta->removeRepo($uri);
		if (! -e $file_name) {
			printf STDERR ("\n    $pem");
			printf STDERR ("\n    refers to $file_name");
			printf STDERR ("\n    which not exist\n");
		}
		$pem = inproc_path(ta => $ta, cert => $file_name, 
					 rootdir => $odir);
		if (! -e $pem) {
			convert_cert(in => $file_name,
				     out => $pem);
		}
		push @chain, $pem;
		$uri = cert_issuer_uri($pem);
	}

	return @chain;
}

#
# Gets the certificate that signed this one.
#
# Usage:
#     $uri = cert_issuer_uri($pem_cert);
#	
# Returns:
#     the uri when there is one, undef otherwise.
#
sub cert_issuer_uri {
	my $pem = shift;

	my @text = qx/openssl x509 -in $pem -text -noout 2>&1/;

	my @uris = grep { /CA Issuers/; } @text;

	if (!@uris) {
		return undef;
	}
	# Assume there is only one, when there are multiples take the first. 
	if ($uris[0] =~ /URI:(.*\.cer)/) {
		return $1;
	}

	return undef;
}

#
# Validates a certificate chain
#
# Usage:
#     valid_chain($target, $i1, $i2 ... $in, $root_cert);
#
# Returns:
#     true if the chain is valid
#     false if it is not
sub valid_chain {
	my $target = shift;
	my $ca = pop @_;
	my @certs = @_;

	my $cmd = "openssl verify -CAfile $ca ";
	for (@certs) {
		$cmd .= "-untrusted $_ ";
	}
	$cmd .= " $target";

	my @output = qx/$cmd 2>&1/;
	if (grep {/error/i;} @output) {
		return undef;
	}
	if (grep {/OK/} @output) {
		return 1;
	}

	return undef;
}

#
# Processes a single ROA 
#
# Usage:
#     $ok = process_cert(ta => $ta,
#                        rootdir => $dir,
#                        roa => $roa);
#
# Returns:
#     true if processing was successful
#     undef if processing failed
#
sub process_roa {
	my (%args, $ta, $rootdir, $roa_file);
	%args = @_;
	($ta, $rootdir, $roa_file) = @args{'ta', 'rootdir', 'roa'};

	printf("Processing roa %s ... ", basename($roa_file));
	my $roa = new ROA();
	$roa->setCMSFile(filename => $roa_file);

	#
	# The EE certificate needs to be extracted.
	#
	my $roa_in_proc_fname = inproc_path(%args, cert => $roa_file);
	copy($roa_file, $roa_in_proc_fname);

	my $ee_in_proc_fname = inproc_path(%args, cert => $roa->EEFileName());
	my $cfg_in_proc_fname = inproc_path(%args, cert => $roa->cfgFileName());
	if (! -e $ee_in_proc_fname || ! -e $cfg_in_proc_fname) {
		# EE certificate doesn't exist, definitely need to extract it
		# Part of extracting the certificate will give us the ROA data,
		# which we'll store in the destination directory as well.
		$roa->readCMSFile(dumpEE => 1, dumpCfg => 1);

		my $ee_file = $roa->EEFileName();
		File::Path::make_path(dirname($ee_in_proc_fname));
		move($ee_file, $ee_in_proc_fname);

		my $cfg_file = $roa->cfgFileName();
		File::Path::make_path(dirname($cfg_in_proc_fname));
		move($cfg_file, $cfg_in_proc_fname);
	}


	# The EE certificate needs to be validated
	my @cert_chain = cert_chain(ta => $ta, rootdir => $rootdir,
				    pem => $ee_in_proc_fname); 
	if ($#cert_chain == 0) {
		# huge problem.
		return undef;
	}
	my $ok = valid_chain(@cert_chain);

	#
	# Now we know if the certificate is valid, time to move the ROA, the
	# Certificate, and the extracted data 
	#

	my $path_maker;
	if ($ok) {
		# valid
		printf("valid EE certificate\n");
		$path_maker = \&valid_path;
	} else {
		printf("invalid EE certificate\n");
		$path_maker = \&invalid_path;
	}

	for my $file ($roa_in_proc_fname, $ee_in_proc_fname, $cfg_in_proc_fname) {
		my $path = $path_maker->(ta => $ta, rootdir => $rootdir,
					 cert => $file);
		File::Path::make_path(dirname($path));
		copy($file, $path);
	}

	return 1;
}


exit main();

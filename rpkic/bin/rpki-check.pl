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
use Getopt::Long qw(:config posix_default auto_help);
use Config::Simple;
use File::Find;
use DBI;
use Data::Dumper;
use Net::IP;

=head1 NAME

rpki-check.pl

=head1 SYNOPSIS

    rpki-check.pl <network> <as>

=cut

#
# False entry point to give some structure to perl.
#
sub main {
	my %opts;
	my $ok = parse_args(\%opts);
	
	my $net = shift @ARGV;
	my $as = shift @ARGV;

	my $dbh = DBI->connect("dbi:Pg:dbname=rpkic", "postgres", "");
	if (!$dbh) {
		printf STDERR "Unable to connect to rpkic\n";
		return 1;
	}

	my @matches = adv_matches($dbh, $net, $as);

	display_results(@matches);

	return 0;
}

sub adv_matches {
	my ($dbh, $net, $as);
	($dbh, $net, $as) = @_;
	my $source = new Net::IP($net);
	if (!$source) {
		printf STDERR ("Malformed network description $net\n");
		printf STDERR ("Check no bits are set in the address beyond the"
			       . " prefix length\n");
		return ();
	}

	my $query = qq{
SELECT roa_pfx, roa_pfx_len_max, roa_as, roa_state_name, cert_src_uri,
       cert_issue_date, cert_expiry_date
 FROM roa, roa_state, cert
WHERE '$net' <<= roa_pfx
  AND roa.cert_id = cert.cert_id
  AND roa.roa_state_id = roa_state.roa_state_id
};
	
	if (defined($as)) {
	    $query .= "AND roa_as = $as";
	}

	my @matches;

	my $sth = $dbh->prepare($query);
	$sth->execute();
	while (my $row = $sth->fetchrow_hashref) {
		my $target = new Net::IP($row->{'roa_pfx'});
		my $len = $row->{'roa_pfx_len_max'};
		if (!defined($len)) {
			$len = $target->prefixlen();
		}

		if ($source->prefixlen() > $len) {
			# The source had a longer prefix length than
			# this match. 
			next;
		}
		push @matches, $row;
	}
	$sth->finish();

	return @matches;
}

sub display_results {
	print $#_ + 1, " Matches\n";
	for my $roa (@_) {
		my $ip = new Net::IP($roa->{'roa_pfx'});
		my $len = $roa->{'roa_pfx_len_max'};
		if (!defined($len)) {
			$len = $ip->prefixlen();
		}
		my $before = $roa->{'cert_expiry_date'};
		$before = "n/a" unless $before;
		my $after = $roa->{'cert_issue_date'};
		$after = "n/a" unless $after;
		print $roa->{'cert_src_uri'}, "\n";
		print "\tValid Before: ", $before;
		print "\tValid After: " , $after;
		print "\n\tNetwork Range: ", $roa->{'roa_pfx'}, "-$len";
		print "\tAS: ", $roa->{'roa_as'};
		print "\n\tCertificate Validity: ", $roa->{'roa_state_name'},"\n";
	}
}


#
# parses the command line arguments
#
sub parse_args {
	my $opts = shift;

	my $ok = GetOptions("usage" => \$opts->{'usage'});

	if ($opts->{'usage'}) {
		pod2usage(-noperldoc => 1);
		return undef;
	}

	if (!$ok) {
		return undef;
	}
	return 1;
}

exit main();

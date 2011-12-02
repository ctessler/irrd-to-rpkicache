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
use IO::Socket;

=head1 NAME

rpki-check.pl

=head1 SYNOPSIS

    rpki-check.pl <network> <as>

=cut

my $DONE = undef;
$SIG{'INT'} = sub { $DONE = '1'; };

#
# False entry point to give some structure to perl.
#
sub main {
	my %opts;
	my $ok = parse_args(\%opts);
	
	my $net = shift @ARGV;
	my $as = shift @ARGV;

	# Daemonize
	{ 
		my $pid = fork();
		exit if $pid;
	}

	my $server = IO::Socket::INET->new(LocalPort => 4096,
					   Type => SOCK_STREAM,
					   Reuse => 1,
					   Listen => 10,
	    ) or die;
	while (!defined($DONE)) {
		my $client = $server->accept();
		if (!defined($client)) {
			next;
		}
		
		$SIG{'CHLD'} = 'IGNORE';
		my $kid = fork();
		if ($kid != 0) {
			# The parent.
			next;
		}

		$client->timeout(3); # give operations 3 seconds to complete
		$client->send("RPKI Cache Server Version: 1\n");

		$SIG{ALRM} = sub {
			$client->send("Timeout disconnecting \n");
			$client->close();
			exit(0);
		};

		alarm(60); # 60 seconds is all you get.

		my $dbh = get_dbh();
		if (!$dbh) {
			$client->send("Unable to connect to database\n");
			$client->send("... disconnecting\n");
			$client->close();
			next;
		}

		my $time = get_last_mod($dbh);
		$time = "Uknown" if (!$time);
		$client->send("Last updated: $time\nrpkic> ");

		# read the network
		my $network;
		do {
			my $buf;
			$client->recv($buf, 1024);
			$network .= $buf;
			chomp($network);
			$network =~ s/[\r]//;
			if ($DONE) {
				last;
			}
		} while ($network !~ /network.*{(.*)}/);
		if ($network =~ /network.*{\s*([^\s]+)\s*}/) {
			$network = $1;
		}

		# Convert the network
		my $net = new Net::IP($network);
		if (!$net) {
			$client->send("ERROR: malformed network: '$network'\n");
			$client->close();
			next;
		}

		# network was validated above
		my @matches = adv_matches($dbh, $network);
		
		$client->send(produce_results(@matches));
		
		$client->close();

		# Only kids get here.
		exit(0);
	}

	printf "Closing server\n";
	$server->close();

	return 0;
}

sub adv_matches {
	my ($dbh, $net);
	($dbh, $net) = @_;
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

sub produce_results {
	my $string;
	$string = "Matches: " . ($#_ + 1) . "\n";

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

		$string .= "\nURI:\t" . $roa->{'cert_src_uri'} . "\n";
		$string .= "AS:\t" . $roa->{'roa_as'} . "\n";
		$string .= "Network Range:\t" . $roa->{'roa_pfx'} . "-$len" . "\n";
		$string .= "Valid After:\t" . $after . "\n";
		$string .= "Valid Before:\t" . $before . "\n";
		$string .= "Validity:\t" . $roa->{'roa_state_name'} ."\n";
	}

	return $string;
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

#
# Gets a new DBH handle.
#
# Mostly a shortcut, we don't want the children to concurrently access the same
# handle.
#
sub get_dbh {
	my $dbh = DBI->connect("dbi:Pg:dbname=rpkic", "postgres", "");
	return $dbh;
}

#
# Gets the last updated time from the database.
#
sub get_last_mod {
	my $dbh = shift;

	my $query = qq{select last_update from update};
	my $sth = $dbh->prepare($query);

	if (!$sth) {
		return undef;
	}
	$sth->execute();

	my $aref = $sth->fetchrow_arrayref();
	if (!$aref) {
		return undef;
	}

	return $aref->[0];
}

exit main();

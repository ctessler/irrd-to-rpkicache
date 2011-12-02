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
use File::Find;
use DBI;
use Data::Dumper;

my @INVALID_ROA;
my @VALID_ROA;

sub roa_check {
	my $orig = $_;
	if ($orig !~ /\.roa$/) {
		return;
	}

	my $cfgf = cfg_file($_);
	my ($cs, %config);

	$cs = new Config::Simple(syntax=>'ini');
	$cs->read($cfgf);
	%config = $cs->vars();

	if ($orig =~ /invalid\/?/) {
		push @INVALID_ROA, \%config;
		return;
	}
	if ($orig =~ /valid\/?/) {
		push @VALID_ROA, \%config;
		return;
	}

}

#
# False entrypoint to give some structure to perl.
#
sub main {
	find({wanted => \&roa_check, no_chdir => 1}, '.');

	print "Found " . @INVALID_ROA . " invalid ROAs\n";
	print "Found " . @VALID_ROA . " valid ROAs\n";

	my $dbh = DBI->connect("dbi:Pg:dbname=rpkic", "postgres", "");
	if (!$dbh) {
		printf STDERR "Unable to connect to rpkic\n";
		return 1;
	}
	
	#
	# Clear the contents of the database
	#
	$dbh->do("delete from roa");
	$dbh->do("delete from cert");
	$dbh->do("delete from update");
	
	my $date=`date`;
	chomp($date);
	$dbh->do("insert into update (last_update) values ('$date')");
	
	insert_invalids($dbh, @INVALID_ROA) or return -1;
	insert_valids($dbh, @VALID_ROA) or return -1;

	return 0;
}

sub insert_invalids {
	my ($dbh, @roas);
	($dbh, @roas) = @_;

	for (@roas) {
		insert_roa($dbh, $_, 0);
	}
	return 1;
}

sub insert_valids {
	my ($dbh, @roas);
	($dbh, @roas) = @_;

	for (@roas) {
		insert_roa($dbh, $_, 1);
	}
	return 1;
}

sub insert_roa {
	my ($dbh, $roa, $valid);
	($dbh, $roa, $valid) = @_;

	my $cert_id = ins_cert($dbh, $roa) or return undef;
	ins_roa($dbh, $roa, $cert_id, $valid) or return undef;
}


sub cfg_file {
	my $cfg = shift;
	$cfg =~ s/\.roa/\.cfg/;

	return $cfg;
}


#
# Returns the certificate insert query.
#
sub certq {
 	my $query = qq{
INSERT INTO cert (cert_name, cert_src_uri, cert_issue_date, cert_expiry_date)
VALUES (?, ?, ?, ?)
RETURNING cert_id
};

	return $query
}	

#
# Inserts the certificate associated with the ROA, returning the
# certificate ID from the database.
#
# Usage:
#     $cert_id = ins_cert($dbh, $roa);
#
sub ins_cert {
	my $dbh = shift;
	my $roa = shift;

	my $certq = certq();

	my $sth = $dbh->prepare($certq);
	my $ok = $sth->execute($roa->{'default.cn'}, $roa->{'default.uri'},
			       $roa->{'default.not_before'}, $roa->{'default.not_after'});
	if (!$ok) {
		printf STDERR ("Could not insert cert%s\n", $roa->{'cn'});
		return undef;
	}
	my $cert_id = $sth->fetchrow_hashref()->{'cert_id'};
	$sth->finish();

	return $cert_id;
}

#
# Returns the ROA existence query
#
sub roa_existq {
	my $query = qq{
SELECT roa_pfx, roa_as, roa_pfx_len_max
FROM roa
WHERE roa_pfx = ? AND
      roa_as = ?
};

	return $query;
}

#
# Returns the ROA insertion query.
#
# Usage:
#     $query = roa_insq($valid);
#
sub roa_insq {
	my $valid = shift;
	if ($valid) {
		$valid= "valid";
	} else {
		$valid = "invalid";
	}
	

	my $query = qq{
INSERT INTO roa (roa_pfx, roa_pfx_len_max, roa_as, cert_id, roa_state_id)
VALUES (?, ?, ?, ?,
	  (SELECT roa_state.roa_state_id
	   FROM roa_state
	   WHERE roa_state.roa_state_name = '$valid'))
};
	return $query;
}

#
# Inserts the ROA and it's network into the database.
#
# Usage:
#     ins_roa($dbh, $roa, $cert_id, $valid)
#
#
sub ins_roa {
	my ($dbh, $roa, $cert_id, $valid);
	($dbh, $roa, $cert_id, $valid) = @_;

	my $insq = roa_insq($valid);
	my $insh = $dbh->prepare($insq);
	
	for my $key (keys %{$roa}) {
		if ($key !~ /^net.v[46]:\d+/) {
			next;
		}
		my $net = $roa->{$key};
		my $as = $roa->{'roa.AS:0'};
		$net =~ s/\-(\d+)$//;
		my $max_len = $1;

		roa_rm_less_spec($dbh, $net, $max_len, $as) or next;
		$insh->execute($net, $max_len, $as, $cert_id);
	}
	$insh->finish();
}


#
# Checks for and removes less specific ROAs than the provided ROA. 
#
# Usage:
#     roa_rm_less_spec($dbh, $pfx, $pfx_max, $as)
#
# Returns:
#     true if the provided specification is most specific
#     undef otherwise.
#
sub roa_rm_less_spec {
	my ($dbh, $pfx, $pfx_max, $as);
	($dbh, $pfx, $pfx_max, $as) = @_;

	# Find a match
	my $existq = roa_existq();
	my $existh = $dbh->prepare($existq);

	$existh->execute($pfx, $as);
	my $row = $existh->fetchrow_hashref();
	$existh->finish();
	if (!$row) {
		# No match.
		return 1;
	}

	# Matched spec more specific than the provided one?
	if (!defined($pfx_max) && defined($row->{'roa_pfx_len_max'})) {
		#DB value is more specific than provided 
		return undef;
	}

	if (!defined($pfx_max) && !defined($row->{'roa_pfx_len_max'})){
		# Pure duplicate
		return undef;
	}

	if (defined($pfx_max) && defined($row->{'roa_pfx_len_max'})) {
		if ($pfx_max <= $row->{'roa_pfx_len_max'}) {
			# DB value is more specific
			return undef;
		}
	}

	#
	# Reaching this point in the function indicates that the DB value must
	# be removed.
	#

	my $delq = qq{DELETE FROM roa WHERE roa_pfx = '$pfx' AND roa_as = $as};
	$dbh->do($delq);

	return 1;
}

exit main();

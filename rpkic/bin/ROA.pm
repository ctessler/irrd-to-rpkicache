#
# (cperl-mode)
# (setq cperl-indent-level 8)
# (setq perl-indent-level 8)
#
package ROA;
use Carp;
use Config::Simple;

=head1 METHODS

=head2 new()

    $roa = new ROA();

Creates a new Resource Origination Attestation

=cut

sub new {
	my $cname = shift;
	$cname = ref($cname) || $cname;

	my %args = @_;

	my $self = {
		filename => undef,
		as_list => [ ],
		v4_nets => [ ],
		v6_nets => [ ],
	};
	bless ($self, $cname);

	return $self;
}

=head2 setCMSFile()

    $ok = $roa->setCMSFile(filename => $path);

This method sets the CMS file name of the ROA. To parse the contents
  of the file see C<readCMSFile()>

=cut

sub setCMSFile {
	my $self = shift;
	my %args = @_;
	my $filename = $args{'filename'};

	if (!defined($filename)) {
		carp "ROA::setCMSFile No filename provided";
		return undef;
	}
	
	$self->{'filename'} = $filename;

	return 1;
}

=head2 getCMSFile()

    $string = $roa->getCMSFile();

This method returns the current CMS file that could be used by
C<readCMSFile>. 

=cut

sub getCMSFile {
	return $_[0]->{'filename'};
}


=head2 readCMSFile()

    $ok = $roa->readCMSFile(dumpEE => [1|undef],
                            dumpCfg => [1|undef]);

This method reads the contents of the CMS file as provided by
C<setCMSFile()>.  When C<dumpEE> is defined, a new PEM certificate
will be created while reading in the CMS file. The filename will be
the same name as the CMS file, with a I<.pem> extension in place of
I<.roa> 

=cut

sub readCMSFile {
	my $self = shift;
	my %args = @_;
	my ($dumpEE, $dumpCfg);
	($dumpEE, $dumpCfg) = @args{'dumpEE', 'dumpCfg'};
	my $cmsfile = $self->getCMSFile();

	if (!defined($cmsfile)) {
		carp "ROA::readCMSFile no CMS file set, see setCMSFile()";
		return undef;
	}

	my $cmd = "print_roa ";
	if ($dumpEE) {
		$cmd .= "-e ";
	}
	$cmd .= $cmsfile;

	my @output = qx/$cmd/;

	chomp @output;
	my $begin_v4, $begin_v6;
	for my $line (@output) {
		if ($line =~ /^asID:\s+(\d+)/) {
			$self->addAS(as => $1);
			$begin_v4 = undef;
			$begin_v6 = undef;
			next;
		}
		if ($line =~ /addressFamily:\s+1/) {
			$begin_v4 = 1;
			$begin_v6 = undef;
			next;
		}
		if ($line =~ /addressFamily:\s+2/) {
			$begin_v4 = undef;
			$begin_v6 = 1;
			next;
		}

		if ($line =~ /IPaddress:\s+(\d+.*)$/) {
			if ($begin_v4) {
				$self->addV4Net(net => $1);
			}
			if ($begin_v6) {
				$self->addV6Net(net => $1);
			}
		}
	}

	#
	# Pick up the information from the EE file
	#
	$self->readEE($self->EEFileName());

	if ($dumpCfg) {
		$self->writeCfg();
	}

	return 1;
}

=head2 EEFileName()

    $file_name = $roa->EEFileName();

This method returns the path to the EE certificate that will be (or was)
extracted from the ROA. To extract the certificate use the C<readCMSFile()>
method, with C<dumpEE> defined.

Upon success the path is returned, otherwise undef.

=cut

sub EEFileName {
	my $self = shift;
	my $cms_file = $self->getCMSFile();

	if (!defined($cms_file)) {
		return undef;
	}

	$cms_file =~ s/\.roa/\.pem/;

	return $cms_file;
}

=head2 cfgFileName()

    $file_name = $roa->cfgFileName();

This method returns the path to the configuration file that will be (or was)
written as a result of reading the ROA. To have the configuration file written
use the C<readCMSFile()> method, with C<dumpCfg> defined.

Upon success the path is returned, otherwise undef.

=cut

sub cfgFileName {
	my $self = shift;
	my $cfg_file = $self->getCMSFile();

	if (!defined($cfg_file)) {
		return undef;
	}

	$cfg_file =~ s/\.roa/\.cfg/;

	return $cfg_file;
}

sub readEE {
	my $self = shift;
	my $ee_file = shift;

	my $cmd = "openssl x509 -in $ee_file -text -noout";
	my @output = qx/$cmd/;
	chomp (@output);

	my $pull_uri;
	for my $line (@output) {
		if ($pull_uri) {
			$pull_uri = undef;
			if ($line =~ /URI:(.*\.roa)/) {
				$self->setURI($1);
			}
			next;
		}

		if ($line =~ /Subject.*CN\=(.*)/) {
			$self->setCN($1);
			next;
		}

		if ($line =~ /Not Before:\s+(.*)GMT/) {
			$self->setBeforeDate($1);
			next;
		}
		if ($line =~ /Not After\s+:\s+(.*)GMT/) {
			$self->setAfterDate($1);
			next;
		}
		if ($line =~ /Subject Information Access:/) {
			$pull_uri = 1;
			next;
		}
	}
}

=head2 addAS

    $self->addAS(as => $asNumber);

=cut

sub addAS {
	my $self = shift;
	my %args = @_;
	my $as = $args{'as'};

	if (!defined($as)) {
		return;
	}

	push @{$self->{'as_list'}}, $as;
}

sub addV4Net {
	my $self = shift;
	my %args = @_;
	
	my $net = $args{'net'};

	if (!defined($net)) {
		return;
	}

	push @{$self->{'v4_nets'}}, $net;
}

sub addV6Net {
	my $self = shift;
	my %args = @_;
	
	my $net = $args{'net'};

	if (!defined($net)) {
		return;
	}

	push @{$self->{'v6_nets'}}, $net;
}

sub writeCfg {
	my $self = shift;

	my $cfg = new Config::Simple(syntax => 'ini');

	my @ass = @{$self->{'as_list'}};
	my @v4s = @{$self->{'v4_nets'}};
	my @v6s = @{$self->{'v6_nets'}};
		
	my $i;
	for ($i = 0; $i <= $#ass; $i++) {
		$cfg->param("roa.AS:$i", $ass[$i]);
	}
	for ($i = 0; $i <= $#v4s; $i++) {
		$cfg->param("net.v4:$i", $v4s[$i]);
	}
	for ($i = 0; $i <= $#v6s; $i++) {
		$cfg->param("net.v6:$i", $v6s[$i]);
	}

	$cfg->param("uri", $self->getURI());
	$cfg->param("not_before", $self->getBeforeDate());
	$cfg->param("not_after", $self->getAfterDate());
	$cfg->param("cn", $self->getCN());
	

	$cfg->write($self->cfgFileName());
}


sub setURI {
	$_[0]->{'uri'} = $_[1];
}

sub getURI {
	return $_[0]->{'uri'};
}

sub setBeforeDate {
	$_[0]->{'beforeDate'} = $_[1];
}

sub getBeforeDate {
	return $_[0]->{'beforeDate'};
}

sub setAfterDate {
	$_[0]->{'afterDate'} = $_[1];
}
	
sub getAfterDate {
	return $_[0]->{'afterDate'};
}

sub setCN {
	$_[0]->{'cn'} = $1;
}

sub getCN {
	return $_[0]->{'cn'};
}

1;

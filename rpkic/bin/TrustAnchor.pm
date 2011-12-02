#
# (cperl-mode)
# (setq cperl-indent-level 8)
# (setq perl-indent-level 8)
#
package TrustAnchor;

=head1 METHODS

=head2 new()

    $ta = new TrustAnchor();

Creates a new TrustAnchor. Upon success a reference is returned. Upon failure
undef. 

=cut

sub new {
	my $cname = shift;
	$cname = ref($cname) || $cname;

	my %args = @_;

	my $self = {repos => {}};
	bless ($self, $cname);

	if (defined($args{'name'})) {
		$self->setName($args{'name'});
	}

	return $self;
}


=head2 setName()

    $ta->setName($name);

Sets the name of the TrustAnchor.

=cut

sub setName {
	my ($self, $name);
	($self, $name) = @_;

	if (!defined($name)) {
		return;
	}

	$self->{'name'} = $name;
}

=head2 getName()

    $name = $ta->getName();

Returns the name of the TrustAnchor, may be undef.

=cut

sub getName {
	return $_[0]->{'name'};
}

=head2 addRepo()

    $ok = $ta->addRepo(dir => $directory,
                       uri => $uri);

This method adds a repository to the TrustAnchor. Invoking this method indicates
that the C<$directory) contains the entire contents of the C<$uri>.

Upon success true is returned, upon failure undef

=cut

sub addRepo {
	my ($self, %args);
	($self, %args) = @_;
	($dir, $uri) = @args{'dir', 'uri'};

	if (!defined($dir)) {
		return undef;
	}
	if (!defined($uri)) {
		return undef;
	}

	if (defined($self->{'repos'}->{$uri})) {
		return undef;
	}

	$self->{'repos'}->{$uri} = $dir;

	return 1;
}

=head2 getCerts()

    @fileList = $ta->getCerts();

This method returns all of filenamse for the certificates found within the Trust
Anchor directories.

=cut
our @FILES;
sub getCerts {
	use File::Find;

	my $self = shift;

	my (@dirs);
	@FILES = ();
	@dirs = values (%{$self->{'repos'}});

	sub cert_store {
		if (/\.cer$/) {
			push @FILES, $_;
		}
	}

	find({wanted => \&cert_store, no_chdir => 1}, @dirs);

	return @FILES;
}

=head2 getROAs()

    @fileList = $ta->geROAs();

This method returns the filenames for all of the ROAs found within the Trust
Anchor's directories.

=cut

sub getROAs {
	use File::Find;

	my $self = shift;
	
	my @dirs = values(%{$self->{'repos'}});
	@FILES = ();
	sub store {
		if (/\.roa$/) {
			push @FILES, $_;
		}
	}

	find({wanted => \&store, no_chdir => 1}, @dirs);
	
	return @FILES;
}


=head2 removeRepo()

    $file = $ta->removeRepo($uri);

Removes the repository root from the uri.

=cut

sub removeRepo {
	my ($self, $uri);
	($self, $uri) = @_;

	for my $key (keys %{$self->{'repos'}}) {
		my $dir = $self->{'repos'}->{$key};
		$uri =~ s/$key/$dir/;
	}

	return $uri;
}


1;

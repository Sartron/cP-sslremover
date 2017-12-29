#!/usr/local/cpanel/3rdparty/bin/perl

use strict;
use warnings;

use Cpanel::SSL::Auto::Config();
use Cpanel::SSL::Auto::Providers();
use Cpanel::SSL::Objects::Certificate();
use Cpanel::SSLStorage::Installed();
use Cpanel::SSLStorage::User();

use Data::Dumper;

sub SSLObject
{
    my $obj =
	{
		id => $_[0],
		modulus => $_[1],
		type => $_[2],
		value => $_[3],
		x509 => $_[4],
    };
	
    return $obj;
}

sub GetStorage
{
	# @sslstorage_array_unparsed is the dumped array from that object.
	# $sslstorage_array_parsed is the actual array reference with the SSL hashes.
	my @sslstorage_array_unparsed = $_[0]->export();
	my $sslstorage_array_parsed = $sslstorage_array_unparsed[1];
	
	# Generate AutoSSL provider varaible as well. This is needed to retrieve AutoSSL providers for certificate objects.
	my $autossl_curproviders = Cpanel::SSL::Auto::Providers->new();
	
	# Parse the SSL storage.
	my @sslobjects;
	foreach my $ssl_item (@$sslstorage_array_parsed)
	{
		# Get generic information about the object.
		my $x509_values = undef;
		my $type = $ssl_item->{'type'};
		my $value = $ssl_item->{'text'};
		my $id = $ssl_item->{'data'}{'id'};
		my $modulus = $ssl_item->{'data'}{'modulus'};
		
		if ($type eq 'certificate')
		{
			# Assign default boolean values to several variables.
			# These will be flipped to true based on code below.
			my $selfsigned = 'False';
			my $autossl = 'False';
			my $expired = 'False';
			
			# Generate Cpanel::SSL::Objects::Certificate object.
			my %cert_x509_hash;
			$cert_x509_hash{'cert'} = $ssl_item->{'text'};
			my $certificate = Cpanel::SSL::Objects::Certificate->new(%cert_x509_hash);
			
			# Check if certificate is self-signed.
			$selfsigned = 'True' if ($certificate->{'parsed'}{'is_self_signed'} == 1);
			
			# Check if certificate is expired.
			$expired = 'True' if ($certificate->expired() == 1);
			
			# Check if certificate is AutoSSL.
			$autossl = 'True' if $autossl_curproviders->get_provider_object_for_certificate_object($certificate);
			
			# Create variable with all certificate information.
			$x509_values =
			{
				selfsigned => $selfsigned,
				autossl => $autossl,
				expired =>
				{
					status => $expired,
					issue_date => $certificate->{'parsed'}{'not_before'},
					expire_date => $certificate->{'parsed'}{'not_after'},
				},
			};
		}
		
		# Create SSL object based on data collected.
		my $sslobj = SSLObject($id, $modulus, $type, $value, $x509_values);
		
		push @sslobjects, $sslobj;
	}
	
	return @sslobjects;
}

sub Main
{
	# Retrieve SSL storage for the specified user.
	# $sslstorage_base is the base Cpanel::SSLStorage::User object.
	my $sslstorage_base = Cpanel::SSLStorage::User->new(user => $_[0]);
	die "No SSL storage returned for user '$_[0]'" if (! $sslstorage_base);
	
	# Here's an array full of hash objects that represent each SSL storage item.
	my @sslstorage_objectcollection = GetStorage($sslstorage_base);
}

exit 1 if ! @ARGV;

Main(@ARGV);
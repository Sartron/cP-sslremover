#!/usr/local/cpanel/3rdparty/bin/perl

use strict;
use warnings;

use Cpanel::SSL::Auto::Config();
use Cpanel::SSL::Auto::Providers();
use Cpanel::SSL::Objects::Certificate();
use Cpanel::SSLStorage::Installed();
use Cpanel::SSLStorage::User();

use Switch;
use YAML 'Dump';

use Data::Dumper;
use Getopt::Long;
Getopt::Long::Configure('posix_default', 'bundling', 'no_ignore_case');

my $VERSION='';
my $UPDATED='January 3 2018';

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
		my $value =
		{
			x509 => ($type eq 'certificate') ? $ssl_item->{'text'} : undef,
			rsa => ($type eq 'key') ? $ssl_item->{'text'} : undef,
		};
		my $id = $ssl_item->{'data'}{'id'};
		my $modulus = $ssl_item->{'data'}{'modulus'};
		
		# Excluding keys for the time being.
		next if ($type ne 'certificate');
		
		if ($type eq 'certificate')
		{
			# Assign default boolean values to several variables.
			# These will be flipped to true based on code below.
			my $signed = 'False';
			my $autossl = 'False';
			my $expired = 'False';
			my $installed = 'False';
			
			
			
			# Generate Cpanel::SSL::Objects::Certificate object.
			my %cert_x509_hash =
			(
				cert => $ssl_item->{'text'},
			);
			my $certificate = Cpanel::SSL::Objects::Certificate->new(%cert_x509_hash);
			
			# Check if certificate is self-signed.
			$signed = 'True' if ($certificate->{'parsed'}{'is_self_signed'} == 0);
			
			# Check if certificate is expired.
			$expired = 'True' if ($certificate->expired() == 1);
			
			# Check if certificate is AutoSSL.
			$autossl = 'True' if $autossl_curproviders->get_provider_object_for_certificate_object($certificate);
			
			# Check if certificate is installed.
			my $installed_sites = $_[1]->get_certificate_domain_installs($id);
			if (ref($installed_sites) eq 'ARRAY')
			{
				$installed = 'True';
			}
			else
			{
				$installed_sites = undef;
			}
			
			# Create variable with all certificate information.
			$x509_values =
			{
				signed => $signed,
				autossl => $autossl,
				expired =>
				{
					status => $expired,
					issue_date => $certificate->{'parsed'}{'not_before'},
					expire_date => $certificate->{'parsed'}{'not_after'},
				},
				installed =>
				{
					status => $installed,
					domains => $installed_sites,
				},
			};
			
			# Find a matching RSA key if possible.
			my $foundkey = $_[0]->find_keys(modulus => $modulus);
			$value->{'rsa'} = $_[0]->get_key_text(@$foundkey[0]->{'id'}) if (scalar(@$foundkey));
		}
		
		# Create SSL object based on data collected.
		my $sslobj = SSLObject($id, $modulus, $type, $value, $x509_values);
		
		# Add newly created object to an array.
		push @sslobjects, $sslobj;
	}
	
	return @sslobjects;
}

sub ShowHelp
{
	print("\e[97mNAME\e[0m
\tcPsslremover - remove ssl objects from cPanel storage

\e[97mOPTIONS\e[0m
\t\e[97mOption			Value		Description\e[0m
\t-u, --user		<string> 	User of certificate

\e[97mCERTIFICATE OPTIONS\e[0m
\t\e[97mOption			Value		Description\e[0m
\t-a, --autossl		<bool>		Certificate was issued by AutoSSL
\t-e, --expired		<bool>		Certificate is expired
\t-i, --installed		<bool>		Certificate is installed
\t-s, --signed		<bool>		Certificate is signed

\e[97mVERSION\e[0m
\tcPsslremover ${VERSION} updated on ${UPDATED}
");
	exit 0;
}

sub LoadOptions
{
	# Initialize variable to store program options.
	my $prog_opts =
	{
		user => undef,
		tests =>
		{
			total => 0,
			autossl => undef,
			expired => undef,
			installed => undef,
			signed => undef,
		},
	};
	
	# Populate options variable.
	GetOptions
	(
		'help|h' => sub { ShowHelp() },
		'user|u=s' => \$prog_opts->{'user'},
		'autossl|a=i' => \$prog_opts->{'tests'}{'autossl'},
		'expired|e=i' => \$prog_opts->{'tests'}{'expired'},
		'installed|i=i' => \$prog_opts->{'tests'}{'installed'},
		'signed|s=i' => \$prog_opts->{'tests'}{'signed'},
	);
	
	# Count up the total amount of tests that will be checked.
	foreach my $var ($prog_opts->{'tests'})
	{
		# Iterate through each key.
		foreach my $_var (keys %$var)
		{
			# Ignore the key total.
			next if ($_var eq 'total');
			
			# Increment the total if the value for the current key is not undefined.
			$prog_opts->{'tests'}{'total'}++ if (defined($prog_opts->{'tests'}{"$_var"}));
		}
	}
	
	# Exit script if no username is provided.
	die 'No username provided' if (! $prog_opts->{'user'});
	
	# Exit script if no tests were provided.
	die 'No tests provided' if ($prog_opts->{'tests'}{'total'} == 0);
	
	return $prog_opts;
}

sub BackupCertificate
{
	# Save the certificate details using the earlier created hash from SSLObject.
	# This is more reliable than using Cpanel::SSLStorage::get_key_path() and Cpanel::SSLStorage::get_certificate_text().
	my $backupdir = 'sslbackups_' . time();
	my $backupfile = "$_[0]->{'id'}.yaml";
	
	# Create directory, then dump the SSL object into a file as YAML.
	mkdir($backupdir);
	open(my $handle, '>', "${backupdir}/${backupfile}") or return;
	print $handle Dump($_[0]);
	close $handle;
}

sub RemoveCertificate
{
	
}

sub Main
{
	# Process all script options.
	my $prog_opts = LoadOptions();
	
	# Retrieve SSL storage for the specified user.
	# $sslstorage_base is the base Cpanel::SSLStorage::User object.
	my $sslstorage_base = Cpanel::SSLStorage::User->new(user => $prog_opts->{'user'});
	die "No SSL storage returned for user '$prog_opts->{'user'}'" if (! $sslstorage_base);
	
	# Retrieve installed SSL storage for the specified user.
	# $sslstorage_base is the base Cpanel::SSLStorage::Installed object.
	my $sslstorage_installed_base = Cpanel::SSLStorage::Installed->new(user => $prog_opts->{'user'});
	
	# Here's an array full of hash objects that represent each SSL storage item.
	my @sslstorage_objectcollection = GetStorage($sslstorage_base, $sslstorage_installed_base);
	
	my $count_obj = '0';
	my $count_obj_total = scalar(@sslstorage_objectcollection);
	foreach my $ssl_obj (@sslstorage_objectcollection)
	{
		# Skip keys.
		next unless ($ssl_obj->{'type'} eq 'certificate');
		
		# Start iterating through each test.
		my $tests_passed = '0';
		my $tests = '';
		foreach my $var ($prog_opts->{'tests'})
		{
			# Iterate through each test.
			foreach my $_var (keys %$var)
			{
				# Ignore the key total and any undefined values.
				next if ($_var eq 'total' || ! defined($prog_opts->{'tests'}{$_var}));
				
				switch ($_var)
				{
					case 'expired'
					{
						if ($ssl_obj->{'x509'}{'expired'}{'status'} eq 'True' && $prog_opts->{'tests'}{$_var} > 0 || $ssl_obj->{'x509'}{'expired'}{'status'} eq 'False' && $prog_opts->{'tests'}{$_var} == 0)
						{
							$tests .= "  ${_var}: \e[32mPassed\e[0m\n";
							$tests_passed++;
						}
						else
						{
							$tests .= "  ${_var}: \e[31mFailed\e[0m\n";
						}
					}
					case 'installed'
					{
						if ($ssl_obj->{'x509'}{'installed'}{'status'} eq 'True' && $prog_opts->{'tests'}{$_var} > 0 || $ssl_obj->{'x509'}{'installed'}{'status'} eq 'False' && $prog_opts->{'tests'}{$_var} == 0)
						{
							$tests .= "  ${_var}: \e[32mPassed\e[0m\n";
							$tests_passed++;
						}
						else
						{
							$tests .= "  ${_var}: \e[31mFailed\e[0m\n";
						}
					}
					else
					{
						# Current Keys
						# signed
						# autossl
						if ($ssl_obj->{'x509'}{$_var} eq 'True' && $prog_opts->{'tests'}{$_var} > 0 || $ssl_obj->{'x509'}{$_var} eq 'False' && $prog_opts->{'tests'}{$_var} == 0)
						{
							$tests .= "  ${_var}: \e[32mPassed\e[0m\n";
							$tests_passed++;
						}
						else
						{
							$tests .= "  ${_var}: \e[31mFailed\e[0m\n";
						}
					}
				}
			}
		}
		
		# This will evaluate true if all user-inputted tests passed.
		if ($tests_passed == $prog_opts->{'tests'}{'total'})
		{
			# Take a backup of all of the certificate's information.
			BackupCertificate($ssl_obj, $sslstorage_base);
			
			# Remove the certificate.
			RemoveCertificate($ssl_obj, $sslstorage_base, $sslstorage_installed_base);
		}
		
		# Output information.
		$count_obj++;
		print("(${count_obj}/${count_obj_total}) $ssl_obj->{'id'} [$prog_opts->{'user'}]
 Criteria Met: ${tests_passed}/$prog_opts->{'tests'}{'total'}
${tests} Backup: 
 Removal: 
");
	}
}

Main(@ARGV);
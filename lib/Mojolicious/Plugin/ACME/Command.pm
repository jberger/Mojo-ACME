package Mojolicious::Plugin::ACME::Command;
use Mojo::Base 'Mojolicious::Command';

has common_usage => sub { shift->extract_usage };

use Mojo::ACME;
use Mojo::URL;
use Getopt::Long qw(GetOptionsFromArray :config no_ignore_case pass_through); # no_auto_abbrev

sub build_acme {
  my ($c, $args) = @_;
  my $acme = Mojo::ACME->new(secret => $c->app->secrets->[0]);
  GetOptionsFromArray( $args,
    'account-key|a=s' => sub { $acme->account_key->path($_[1]) },
    'ca-url|c=s' => \my $ca,
    'test|t' => \my $test,
  );
  die 'Cannot specify ca-url and test at the same time' if $ca && $test;
  $acme->ca(Mojo::URL->new('https://acme-staging.api.letsencrypt.org')) if $test;
  $acme->ca(Mojo::URL->new($ca)) if $ca;
  return $acme;
}

1;

=head1 NAME

Mojolicious::Plugin::ACME::Command - ACME command common functionality

=head1 SYNOPSIS

  Common Options:
    -a, --account-key   file containing your account key
                          defaults to account.key
    -c, --ca-url        url of the ACME service
                          defaults to the letsencrypt primary url
    -t, --test          use the letsencrypt test server (incompatible with -c)
=cut


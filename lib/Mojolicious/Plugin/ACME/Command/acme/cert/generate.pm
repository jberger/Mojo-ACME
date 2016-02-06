package Mojolicious::Plugin::ACME::Command::acme::cert::generate;
use Mojo::Base 'Mojolicious::Plugin::ACME::Command';

use Mojo::Collection 'c';
use Mojo::Util 'spurt';

use Getopt::Long qw(GetOptionsFromArray :config no_ignore_case); # no_auto_abbrev

has description => 'Generate a certificate signed by the ACME service';
has usage => sub {
  my $c = shift;
  $c->extract_usage . $c->common_usage;
};

sub run {
  my ($c, @args) = @_;
  my $acme = $c->build_acme(\@args);
  $acme->server_url($c->app->config('acme')->{client_url});

  GetOptionsFromArray(\@args,
    'name|n=s' => \my $name,
    'domain|d=s' => \my @domains,
    'force|f' => \my $force,
  );
  $name ||= $c->app->moniker;

  push @domains, @args;
  die 'a domain name is required' unless @domains;

  #Note: wildcard domains are at the discrecion of the ACME service and
  #are not supported by letsencrypt, even if they are allowed they are
  #never to be challenged and thus @new is not @domains

  my @new = grep { $_ !~ /^\*/ } @domains;
  die 'ACME does not explicitly allow wildcard certs, use --force to override'
    unless (@new == @domains || $force);

  my $cert;
  Mojo::IOLoop->delay(
    sub { $acme->new_authz($_ => shift->begin) for @new },
    sub { $acme->check_all_challenges(shift->begin) },
    sub {
      my ($delay, $err) = @_;
      die Mojo::Util::dumper($err) if $err;
      my $bad = c(values %{ $acme->challenges })->grep(sub { $_->{status} ne 'valid' });
      die 'The following challenges were not validated ' . Mojo::Util::dumper($bad->to_array) if $bad->size;
      #TODO poll for cert when delayed
      $cert = $acme->get_cert(@domains);
    },
  )->wait;

  die 'No cert was generated' unless $cert;

  if ($acme->cert_key->generated) {
    my $key_path = "$name.key";
    say "Writing $key_path";
    spurt $acme->cert_key->string => $key_path;
  }

  my $cert_path = "$name.crt";
  say "Writing $cert_path";
  spurt $cert => $cert_path;
}

1;

=head1 NAME

Mojolicious::Plugin::ACME::Command::acme::cert::generate - ACME signed certificate generation

=head1 SYNOPSIS

  Usage: APPLICATION acme cert generate [OPTIONS]
    myapp acme cert generate mydomain.com
    myapp acme cert generate -t -a myaccount.key mydomain.com

  Options:
=cut


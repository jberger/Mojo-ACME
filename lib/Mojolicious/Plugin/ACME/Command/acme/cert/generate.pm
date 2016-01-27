package Mojolicious::Plugin::ACME::Command::acme::cert::generate;
use Mojo::Base 'Mojolicious::Plugin::ACME::Command';

use Mojo::Collection 'c';

has description => 'Generate a certificate signed by the ACME service';
has usage => sub {
  my $self = shift;
  $self->extract_usage . $self->common_usage;
};

sub run {
  my ($c, @args) = @_;
  my $acme = $c->build_acme(\@args);
  $acme->server_url($c->app->config('acme')->{client_url});

  Mojo::IOLoop->delay(
    sub { $acme->new_authz('jberger.pl' => shift->begin) },
    sub { $acme->check_all_challenges(shift->begin) },
    sub {
      my ($delay, $err) = @_;
      die Mojo::Util::dumper($err) if $err;
      my $bad = c(values %{ $acme->challenges })->grep(sub { $_->{status} ne 'valid' });
      die 'The following challenges were not validated ' . Mojo::Util::dumper($bad->to_array) if $bad->size;
      print $acme->get_cert('jberger.pl');
    },
  )->wait;
}

1;

=head1 NAME

Mojolicious::Plugin::ACME::Command::acme::cert::generate - ACME signed certificate generation

=head1 SYNOPSIS

  Usage: APPLICATION acme cert generate [OPTIONS]
    myqpp acme cert generate
    myqpp acme cert generate -t -a myaccount.key

  Options:
=cut


package Mojolicious::Plugin::ACME::Command::acme;

use Mojo::Base 'Mojolicious::Command';

use Mojo::ACME;
use Mojo::Collection 'c';

sub run {
  my ($command, @args) = @_;
  my $acme = Mojo::ACME->new(
    server_url => $command->app->config('acme')->{client_url},
  );

  Mojo::IOLoop->delay(
    sub { $acme->new_authz('jberger.pl' => shift->begin) },
    sub { $acme->check_all_challenges(shift->begin) },
    sub {
      my ($delay, $err) = @_;
      die Mojo::Util::dumper($err) if $err;
      my $bad = c(values %{ $acme->tokens })->grep(sub { $_->{status} ne 'valid' });
      die 'The following challenges were not validated ' . Mojo::Util::dumper($bad->to_array) if $bad->size;
      print $acme->get_cert('jberger.pl');
    },
  )->wait;
  #die 'Register failed' unless $acme->register;
  #Mojo::Util::spurt($acme->generate_csr(qw/jberger.pl *.jberger.pl/) => 'out.csr');
  #say $acme->thumbprint;
}

1;


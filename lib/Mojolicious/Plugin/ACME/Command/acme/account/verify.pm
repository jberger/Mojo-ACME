package Mojolicious::Plugin::ACME::Command::acme::account::verify;
use Mojo::Base 'Mojolicious::Plugin::ACME::Command';

has description => 'Verify your account against an ACME service';
has usage => sub {
  my $self = shift;
  $self->extract_usage . $self->common_usage;
};

sub run {
  my ($c, @args) = @_;
  my $acme = $c->build_acme(\@args);
  say $acme->register || die "Not registered\n";
}

1;

=head1 NAME

Mojolicious::Plugin::ACME::Command::acme::account::verify - ACME account verification

=head1 SYNOPSIS

  Usage: APPLICATION acme account verify [OPTIONS]
    myqpp acme account verify
    myqpp acme account verify -t -a myaccount.key

  Options:
=cut


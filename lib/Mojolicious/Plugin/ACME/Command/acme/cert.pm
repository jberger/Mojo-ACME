package Mojolicious::Plugin::ACME::Command::acme::cert;

use Mojo::Base 'Mojolicious::Commands';

has description => 'ACME service certificate commands';
has hint => <<END;

See $0 acme cert help COMMAND for more information on a specific command
END

has message    => sub { shift->extract_usage . "\nCommands:\n" };
has namespaces => sub { [__PACKAGE__] };

1;

=head1 NAME

Mojolicious::Plugin::ACME::Command::acme::cert - ACME certificate commands

=head1 SYNOPSIS

  Usage: APPLICATION acme cert COMMAND [OPTIONS]
    myqpp acme cert generate
    myqpp acme cert revoke

=cut


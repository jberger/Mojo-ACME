package Mojolicious::Plugin::ACME;

use Mojo::Base 'Mojolicious::Plugin';

use Mojo::URL;
use Mojo::UserAgent;

sub register {
  my ($plugin, $app) = @_;
  my $config = $app->config->{acme} ||= {}; #die 'no ACME config found';

  $config->{ca} ||= 'https://acme-staging.api.letsencrypt.org';
  my $url = Mojo::URL->new($config->{client_url} ||= 'http://127.0.0.1:5000');

  push @{ $app->commands->namespaces }, 'Mojolicious::Plugin::ACME::Command';

  my $ua = Mojo::UserAgent->new;
  $app->routes->get('/.well-known/acme-challenge/:token' => sub {
    my $c = shift;
    my $token = $c->stash('token');
    $c->delay(
      sub { $ua->get($url->clone->path("/$token"), shift->begin) },
      sub {
        my ($delay, $tx) = @_;
        return $c->reply->not_found unless $tx->success;
        $c->render(text => $tx->res->body);
      },
    );
  });
}

1;


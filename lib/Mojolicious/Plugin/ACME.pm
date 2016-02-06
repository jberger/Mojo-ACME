package Mojolicious::Plugin::ACME;

use Mojo::Base 'Mojolicious::Plugin';

use Mojo::URL;
use Mojo::UserAgent;
use Mojo::Util 'hmac_sha1_sum';

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
    my $secret = $c->app->secrets->[0];
    my $hmac = hmac_sha1_sum $token, $secret;
    $c->delay(
      sub { $ua->get($url->clone->path("/$token"), {'X-HMAC' => $hmac}, shift->begin) },
      sub {
        my ($delay, $tx) = @_;
        return $c->reply->not_found
          unless $tx->success && (my $auth = $tx->res->text) && (my $hmac_res = $tx->res->headers->header('X-HMAC'));
        return $c->reply->not_found
          unless $hmac_res eq hmac_sha1_sum($auth, $secret);

        $c->render(text => $auth);
      },
    );
  });
}

1;


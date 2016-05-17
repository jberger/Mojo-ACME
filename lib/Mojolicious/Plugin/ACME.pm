package Mojolicious::Plugin::ACME;

use Mojo::Base 'Mojolicious::Plugin';

use Mojo::URL;
use Mojo::UserAgent;
use Mojo::Util qw/hmac_sha1_sum secure_compare/;

use Mojo::ACME::CA;

my %cas = (
  letsencrypt => {
    agreement => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
    name => q[Let's Encrypt],
    intermediate => 'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem',
    primary_url => Mojo::URL->new('https://acme-v01.api.letsencrypt.org'),
    test_url    => Mojo::URL->new('https://acme-staging.api.letsencrypt.org'),
  },
);

sub register {
  my ($plugin, $app) = @_;
  my $config = $app->config->{acme} ||= {}; #die 'no ACME config found';

  %{ $config->{cas} } = (%cas, %{ $config->{cas} || {} }); # merge default CAs #}# highlight fix
  $config->{ca} ||= 'letsencrypt';
  unless (ref $config->{ca}) {
    die 'Unknown CA'
      unless my $spec = $config->{cas}{$config->{ca}};
    $config->{ca} = Mojo::ACME::CA->new($spec);
  }

  my $url = Mojo::URL->new($config->{challenge_url} ||= 'http://127.0.0.1:5000');

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
          unless secure_compare $hmac_res, hmac_sha1_sum($auth, $secret);

        $c->render(text => $auth);
      },
    );
  });
}

1;

=head1 NAME

Mojolicious::Plugin::ACME - ACME client integration for your Mojolicious app



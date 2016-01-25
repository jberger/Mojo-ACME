package Mojolicious::Plugin::ACME::Command::acme;

use Mojo::Base 'Mojolicious::Command';

use Mojo::Collection 'c';
use Mojo::JSON qw/encode_json/;
use Mojo::Server::Daemon;
use Mojo::URL;
use Mojo::Util qw/dumper slurp/;
use Mojolicious;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum; # get_key_parameters
use Crypt::OpenSSL::PKCS10;
use Digest::SHA 'sha256';
use MIME::Base64 qw/encode_base64url/;

has account_file => 'account.key';
has account_key => sub { Crypt::OpenSSL::RSA->new_private_key(slurp(shift->account_file)) };
has account_pub => sub { Crypt::OpenSSL::RSA->new_public_key(shift->account_key->get_public_key_string) };
has ca => sub { Mojo::URL->new('https://acme-staging.api.letsencrypt.org') };
has header => sub {
  my ($n, $e) = shift->account_pub->get_key_parameters;
  return {
    alg => 'RS256',
    jwk => {
      kty => 'RSA',
      e => encode_base64url($e->to_bin),
      n => encode_base64url($n->to_bin),
    },
  };
};
has thumbprint => sub {
  my $jwk = shift->header->{jwk};
  # manually format json for sorted keys
  my $fmt = '{"e":"%s","kty":"%s","n":"%s"}';
  my $json = sprintf $fmt, @{$jwk}{qw/e kty n/};
  return encode_base64url( sha256($json) );
};
has ua => sub { Mojo::UserAgent->new };

sub run {
  my ($command, @args) = @_;

  #die 'Register failed' unless $command->register;
  my $url = $command->ca->clone->path('/acme/new-authz');
  my $req = $command->signed_request({
    resource => 'new-authz',
    identifier => {
      type  => 'dns',
      value => 'jberger.pl',
    },
  });
  my $tx = $command->ua->post($url, $req);
  unless ($tx->res->code == 201) {
    say $tx->res->body;
    die 'Error requesting challenges';
  }

  my $challenges = $tx->res->json('/challenges') || [];
  die 'No http challenge available'
    unless my $http = c(@$challenges)->first(sub{ $_->{type} eq 'http-01' });

  print Mojo::Util::dumper $http;
  exit;

  my $token = $http->{token};
  my $keyauth = $token . '.' . $command->thumbprint;

  my $app = Mojolicious->new;
  my $server = Mojo::Server::Daemon->new(
    app    => $app,
    listen => [$command->app->config('acme')->{client_url}],
  );
  my $seen;
  my $timer = Mojo::IOLoop->timer(5 => sub { $server->stop->ioloop->stop });
  $app->routes->get('/:token' => sub {
    my $c = shift;
    return $c->reply->not_found unless $c->stash('token') eq $token;
    $c->render(text => $keyauth);
    $seen++;
    $server->stop->ioloop->stop;
  });
  $server->start;
  Mojo::IOLoop->start;
  Mojo::IOLoop->remove($timer);
  return $seen;

  #Mojo::Util::spurt($command->generate_csr(qw/jberger.pl *.jberger.pl/) => 'out.csr');
  #say $command->thumbprint;
}

sub get_nonce {
  my $command = shift;
  my $url = $command->ca->clone->path('/directory');
  $command->ua->get($url)->res->headers->header('Replay-Nonce');
}

sub generate_csr {
  my ($command, $primary, @alts) = @_;

  my $rsa = Crypt::OpenSSL::RSA->generate_key(4096);
  my $req = Crypt::OpenSSL::PKCS10->new_from_rsa($rsa);
  $req->set_subject("/CN=$primary");
  if (@alts) {
    my $alt = join ',', map { "DNS:$_" } ($primary, @alts);
    $req->add_ext(Crypt::OpenSSL::PKCS10::NID_subject_alt_name, $alt);
  }
  $req->add_ext_final;
  $req->sign;
  return $req->get_pem_req;
}

sub register {
  my $command = shift;
  my $url = $command->ca->clone->path('/acme/new-reg');
  my $req = $command->signed_request({
    resource => 'new-reg',
    agreement => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
  });
  my $code = $command->ua->post($url, $req)->res->code;
  return $code == 201 || $code == 409;
}

sub signed_request {
  my ($command, $payload) = @_;
  $payload = encode_base64url(encode_json($payload));
  my $key = $command->account_key;
  $key->use_sha256_hash;
  my $header = $command->header;
  my $protected = do {
    local $header->{nonce} = $command->get_nonce;
    encode_base64url(encode_json($header));
  };
  my $sig = encode_base64url($key->sign("$protected.$payload"));
  return encode_json {
    header    => $header,
    payload   => $payload,
    protected => $protected,
    signature => $sig,
  };
}

1;


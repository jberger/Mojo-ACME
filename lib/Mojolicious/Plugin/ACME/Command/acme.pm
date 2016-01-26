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
use Scalar::Util;

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
has server => sub {
  my $command = shift;
  my $app = Mojolicious->new;
  my $server = Mojo::Server::Daemon->new(
    app    => $app,
    listen => [$command->app->config('acme')->{client_url}],
  );
  Scalar::Util::weaken $command;
  $app->routes->get('/:token' => sub {
    my $c = shift;
    my $token = $c->stash('token');
    return $c->reply->not_found
      unless my $cb = delete $command->tokens->{$token}{cb};
    $c->on(finish => sub { $command->$cb($token) });
    $c->render(text => $command->keyauth($token));
  });
  return $server->start;
};
has thumbprint => sub {
  my $jwk = shift->header->{jwk};
  # manually format json for sorted keys
  my $fmt = '{"e":"%s","kty":"%s","n":"%s"}';
  my $json = sprintf $fmt, @{$jwk}{qw/e kty n/};
  return encode_base64url( sha256($json) );
};
has tokens => sub { {} };
has ua => sub { Mojo::UserAgent->new };

sub check_all_challenges {
  my ($command, $cb) = (shift, pop);
  my $tokens = shift || c(keys %{ $command->tokens });
  Mojo::IOLoop->delay(
    sub {
      my $delay = shift;
      $command->check_challenge_status($_, $delay->begin) for @$tokens;
    },
    sub {
      my $delay = shift;
      my $tokens = c(@_)->compact;
      return $command->$cb(undef) unless $tokens->size; # nothing left to check
      if (my $err = $tokens->first(sub{ ref })) { return $command->$cb($err) }
      $command->check_all_challenges($tokens, $cb);
    }
  );
}

sub check_challenge_status {
  my ($command, $token, $cb) = @_;
  return Mojo::IOLoop->next_tick(sub{ $command->$cb({token => $token, message => 'unknown token'}) })
    unless my $challenge = $command->tokens->{$token};
  my $ua = $command->ua;
  $ua->get($challenge->{uri} => sub {
    my ($ua, $tx) = @_;
    my $ret;
    if (my $res = $tx->success) {
      my $status = $res->json('/status');
      if ($status eq 'pending') { $ret = $token }
      elsif ($status ne 'valid') {
        $ret = {token => $token, message => 'challenge failed'}
      }
    } else {
      $ret = $tx->error;
      $ret->{token} = $token;
    }
    $command->$cb($ret);
  });
}

sub run {
  my ($command, @args) = @_;

  Mojo::IOLoop->delay(
    sub { $command->new_authz('jberger.pl' => shift->begin) },
    sub { $command->check_all_challenges(shift->begin) },
    sub {
      my ($delay, $err) = @_;
      return print Mojo::Util::dumper($err) if $err;
      print 'success';
    },
  )->wait;
  #die 'Register failed' unless $command->register;
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

sub keyauth {
  my ($command, $token) = @_;
  return $token . '.' . $command->thumbprint;
}

sub new_authz {
  my ($command, $value, $cb) = @_;
  my $url = $command->ca->clone->path('/acme/new-authz');
  my $req = $command->signed_request({
    resource => 'new-authz',
    identifier => {
      type  => 'dns',
      value => $value,
    },
  });
  my $tx = $command->ua->post($url, $req);
  die 'Error requesting challenges' unless $tx->res->code == 201;

  my $challenges = $tx->res->json('/challenges') || [];
  die 'No http challenge available'
    unless my $challenge = c(@$challenges)->first(sub{ $_->{type} eq 'http-01' });

  my $token = $challenge->{token};
  $challenge->{cb} = $cb;
  $command->tokens->{$token} = $challenge;
  $command->server; #ensure server started

  my $trigger = $command->signed_request({
    resource => 'challenge',
    keyAuthorization => $command->keyauth($token),
  });
  die 'Error triggering challenge'
    unless $command->ua->post($challenge->{uri}, $trigger)->res->code == 202;
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


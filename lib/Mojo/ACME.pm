package Mojo::ACME;

use Mojo::Base -base;

use Mojo::Collection 'c';
use Mojo::JSON qw/encode_json/;
use Mojo::Server::Daemon;
use Mojo::URL;
use Mojo::Util 'hmac_sha1_sum';
use Mojolicious;

use Crypt::OpenSSL::PKCS10;
use MIME::Base64 qw/encode_base64url encode_base64 decode_base64/;
use Scalar::Util;

use Mojo::ACME::Key;

has account_key => sub { Mojo::ACME::Key->new(path => 'account.key') };
has ca => sub { Mojo::URL->new('https://acme-v01.api.letsencrypt.org') };
has challenges => sub { {} };
#TODO use cert_key->key if it exists
has cert_key => sub { Mojo::ACME::Key->new };

has server => sub {
  my $self = shift;
  my $app = Mojolicious->new;
  my $server = Mojo::Server::Daemon->new(
    app    => $app,
    listen => [$self->server_url],
  );
  Scalar::Util::weaken $self;
  $app->routes->get('/:token' => sub {
    my $c = shift;
    my $token = $c->stash('token');
    my $hmac = $c->req->headers->header('X-HMAC');
    my $secret = $self->secret;

    return $c->reply->not_found
      unless my $cb = delete $self->{callbacks}{$token};
    $c->on(finish => sub { $self->$cb($token) });

    return $c->render(text => 'Unauthorized', status => 401)
      unless $hmac eq hmac_sha1_sum($token, $secret);

    my $auth = $self->keyauth($token);
    $c->res->headers->header('X-HMAC' => hmac_sha1_sum($auth, $secret));
    $c->render(text => $auth);
  });
  return $server->start;
};

has secret => sub { die 'secret is required' };
has server_url => 'http://127.0.0.1:5000';
has ua => sub { Mojo::UserAgent->new };

sub check_all_challenges {
  my ($self, $cb) = (shift, pop);
  my @pending = $self->pending_challenges->each;
  Mojo::IOLoop->delay(
    sub {
      my $delay = shift;
      $self->check_challenge_status($_, $delay->begin) for @pending;
    },
    sub {
      my $delay = shift;
      if (my $err = c(@_)->first(sub{ ref })) { return $self->$cb($err) }
      return $self->$cb(undef) unless $self->pending_challenges->size;
      Mojo::IOLoop->timer(2 => $delay->begin);
    },
    sub { $self->check_all_challenges($cb) },
  );
}

sub check_challenge_status {
  my ($self, $token, $cb) = @_;
  return Mojo::IOLoop->next_tick(sub{ $self->$cb({token => $token, message => 'unknown token'}) })
    unless my $challenge = $self->challenges->{$token};
  my $ua = $self->ua;
  $ua->get($challenge->{uri} => sub {
    my ($ua, $tx) = @_;
    my $err;
    if (my $res = $tx->success) {
      $self->challenges->{$token} = $res->json;
    } else {
      $err = $tx->error;
      $err->{token} = $token;
    }
    $self->$cb($err);
  });
}

sub get_cert {
  my ($self, @names) = @_;
  my $csr = _pem_to_der($self->generate_csr(@names));
  my $req = $self->signed_request({
    resource => 'new-cert',
    csr => encode_base64url($csr),
  });
  my $url = $self->ca->clone->path('/acme/new-cert');
  my $tx = $self->ua->post($url, $req);
  die 'failed to get cert' unless $tx->success;
  return _der_to_cert($tx->res->body);
}

sub get_nonce {
  my $self = shift;
  my $url = $self->ca->clone->path('/directory');
  $self->ua->get($url)->res->headers->header('Replay-Nonce');
}

sub generate_csr {
  my ($self, $primary, @alts) = @_;

  my $rsa = $self->cert_key->key_clone;
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
  my ($self, $token) = @_;
  return $token . '.' . $self->account_key->thumbprint;
}

sub new_authz {
  my ($self, $value, $cb) = @_;
  my $url = $self->ca->clone->path('/acme/new-authz');
  my $req = $self->signed_request({
    resource => 'new-authz',
    identifier => {
      type  => 'dns',
      value => $value,
    },
  });
  my $tx = $self->ua->post($url, $req);
  die 'Error requesting challenges' unless $tx->res->code == 201;

  my $challenges = $tx->res->json('/challenges') || [];
  die 'No http challenge available'
    unless my $challenge = c(@$challenges)->first(sub{ $_->{type} eq 'http-01' });

  my $token = $challenge->{token};
  $self->challenges->{$token} = $challenge;
  $self->{callbacks}{$token} = $cb;
  $self->server; #ensure server started

  my $trigger = $self->signed_request({
    resource => 'challenge',
    keyAuthorization => $self->keyauth($token),
  });
  die 'Error triggering challenge'
    unless $self->ua->post($challenge->{uri}, $trigger)->res->code == 202;
}

sub pending_challenges {
  my $self = shift;
  c(values %{ $self->challenges })
    ->grep(sub{ $_->{status} eq 'pending' })
    ->map(sub{ $_->{token} })
}

sub register {
  my $self = shift;
  my $url = $self->ca->clone->path('/acme/new-reg');
  my $req = $self->signed_request({
    resource => 'new-reg',
    agreement => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
  });
  my $code = $self->ua->post($url, $req)->res->code;
  return
    $code == 201 ? 'Account Created' :
    $code == 409 ? 'Account Exists' :
                   undef;
}

sub signed_request {
  my ($self, $payload) = @_;
  $payload = encode_base64url(encode_json($payload));
  my $key = $self->account_key;
  my $jwk = $key->jwk;

  my $header = {
    alg => 'RS256',
    jwk => {%$jwk}, # clone the jwk for safety's sake
  };

  my $protected = do {
    local $header->{nonce} = $self->get_nonce;
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

sub _pem_to_der {
  my $cert = shift;
  $cert =~ s/^-{5}.*$//mg;
  return decode_base64(Mojo::Util::trim($cert));
}

sub _der_to_cert {
  my $der = shift;
  my $pem = encode_base64($der, '');
  $pem =~ s!(.{1,64})!$1\n!g; # stolen from Convert::PEM
  return sprintf "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", $pem;
}

1;

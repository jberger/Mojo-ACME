package Mojo::ACME::Key;

use Mojo::Base -base;

use Mojo::Util;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum; # get_key_parameters
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';

has 'generated';
has string => sub { shift->tap('key')->{string} };
has key => sub {
  my $self = shift;
  my $path = $self->path;
  my $rsa;
  if ($path && -e $path) {
    $self->{string} = Mojo::Util::slurp($path);
    $rsa = Crypt::OpenSSL::RSA->new_private_key($self->{string})
  } else {
    $self->generated(1);
    $rsa = Crypt::OpenSSL::RSA->generate_key(4096);
    $self->{string} = $rsa->get_private_key_string;
  }
  return $rsa;
};
has 'path';
has pub => sub { Crypt::OpenSSL::RSA->new_public_key(shift->key->get_public_key_string) };

has jwk => sub {
  my ($n, $e) = shift->pub->get_key_parameters;
  return {
    kty => 'RSA',
    e => encode_base64url($e->to_bin),
    n => encode_base64url($n->to_bin),
  };
};

has thumbprint => sub {
  my $jwk = shift->jwk;
  # manually format json for sorted keys
  my $fmt = '{"e":"%s","kty":"%s","n":"%s"}';
  my $json = sprintf $fmt, @{$jwk}{qw/e kty n/};
  return encode_base64url( sha256($json) );
};

sub sign {
  my ($self, $content) = @_;
  my $key = $self->key;
  $key->use_sha256_hash;
  return $key->sign($content);
}

1;


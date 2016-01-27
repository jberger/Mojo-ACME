package Mojo::ACME::Key;

use Mojo::Base -base;

use Mojo::Util;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum; # get_key_parameters
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';

has 'path';
has file_contents => sub { Mojo::Util::slurp(shift->path) };

has key => sub { Crypt::OpenSSL::RSA->new_private_key(shift->file_contents) };
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

sub generate {
  my $self = shift;
  #TODO check for existing key and fail if exists
  my $key = Crypt::OpenSSL::RSA->generate_key(4096);
  return $self->key($key)->key;
}

sub sign {
  my ($self, $content) = @_;
  my $key = $self->key;
  $key->use_sha256_hash;
  return $key->sign($content);
}

1;


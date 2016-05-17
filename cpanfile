requires 'Mojolicious', '4.82'; # encode_json
requires 'Crypt::OpenSSL::RSA';
requires 'Crypt::OpenSSL::Bignum'; # get_key_parameters
requires 'Crypt::OpenSSL::PKCS10';
requires 'Digest::SHA';
requires 'MIME::Base64', '3.11'; # url variants
requires 'Safe::Isa';

test_requires 'Mock::MonkeyPatch';

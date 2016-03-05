use Mojo::Base -strict;

use Test::More;
use Mock::MonkeyPatch;
use Mojo::JSON;
use Mojo::URL;
use Mojolicious;

use Mojo::ACME;
use Mojo::ACME::CA;
use Mojo::ACME::Key;

sub test_objects {
  my $acme = Mojo::ACME->new(ca => Mojo::URL->new('/'));
  $acme->ca(Mojo::ACME::CA->new(
    name => 'Test CA',
    primary_url => '/',
    test_url => '/',
  ));
  $acme->ua->server->app(my $mock = Mojolicious->new);
  return ($acme, $mock);
}

subtest 'get nonce' => sub {
  my ($acme, $mock) = test_objects;
  my $directory;
  $mock->routes->get('/directory' => sub {
    my $c = shift;
    $directory++;
    $c->res->headers->header('Replay-Nonce' => 'abc1234');
    $c->rendered(204);
  });

  is $acme->get_nonce, 'abc1234', 'got nonce';
  ok $directory, 'directory handler was called';
};

subtest 'check challenge status' => sub {
  my ($acme, $mock) = test_objects;
  my $fail;
  $mock->routes->get('/fail' => sub { $fail++; shift->reply->not_found });
  $mock->routes->get('/:token' => sub {
    my $c = shift;
    my $token = $c->stash('token');
    $c->render(json => {token => $token, status => 'valid'});
  });

  my $err;
  $acme->check_challenge_status('a1b2c3', sub { (undef, $err) = @_; Mojo::IOLoop->stop });
  Mojo::IOLoop->start;
  is_deeply $err, {token => 'a1b2c3', message => 'unknown token'}, 'token not known';

  undef $err;
  $acme->challenges({ bad1 => {uri => '/fail'} });
  $acme->check_challenge_status('bad1', sub { (undef, $err) = @_; Mojo::IOLoop->stop });
  Mojo::IOLoop->start;
  ok $fail, 'fail handler was called';
  is $err->{code}, 404, 'got error propagated' or diag $mock->dumper($err);

  undef $err;
  $acme->challenges({ good1 => {uri => '/good1'} });
  $acme->check_challenge_status('good1', sub { (undef, $err) = @_; Mojo::IOLoop->stop });
  Mojo::IOLoop->start;
  ok !$err, 'no error';
  is_deeply $acme->challenges->{good1}, {token => 'good1', status => 'valid' }, 'got updated status';
};

subtest 'keyauth' => sub {
  no warnings 'redefine';
  local *Mojo::ACME::Key::thumbprint = sub { 'abcd' };
  my ($acme, $mock) = test_objects;
  is $acme->keyauth('xyz'), 'xyz.abcd', 'correct keyauth';
};

subtest 'generate csr' => sub {
  #TODO improve this test
  my ($acme, $mock) = test_objects;
  $acme->cert_key->path('t/test.key');
  ok $acme->generate_csr('example.com');
};

subtest 'generate signed request body' => sub {
  #TODO improve this test
  my ($acme, $mock) = test_objects;
  $acme->account_key->path('t/test.key');
  ok $acme->signed_request({hello => 'world'});
};

subtest 'account registration' => sub {
  my ($acme, $mock) = test_objects;
  my ($code, $json);
  $mock->routes->post('/acme/new-reg' => sub {
    my $c = shift;
    $json = $c->req->json;
    $c->rendered($code);
  });

  no warnings 'redefine';
  local *Mojo::ACME::signed_request = sub { Mojo::JSON::encode_json($_[1]) };

  my $expect = {
    resource => 'new-reg',
    agreement => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
  };

  subtest 'account created' => sub {
    $code = 201;
    is $acme->register, 'Account Created';
    is_deeply $json, $expect;
    $json = undef;
  };

  subtest 'account exists' => sub {
    $code = 409;
    is $acme->register, 'Account Exists';
    is_deeply $json, $expect;
    $json = undef;
  };

  subtest 'failed' => sub {
    $code = 500;
    ok !$acme->register;
    is_deeply $json, $expect;
    $json = undef;
  };
};

subtest 'get cert' => sub {
  my ($acme, $mock) = test_objects;
  my ($body, $status, $json);
  $mock->routes->post('/acme/new-cert' => sub {
    my $c = shift;
    $json = $c->req->json;
    $c->render(text => $body, status => $status);
  });

  my $signed = Mock::MonkeyPatch->patch('Mojo::ACME::signed_request' => sub { Mojo::JSON::encode_json($_[1]) });
  my $pem_to_der  = Mock::MonkeyPatch->patch('Mojo::ACME::_pem_to_der'  => sub { "DER: $_[0]" });
  my $der_to_cert = Mock::MonkeyPatch->patch('Mojo::ACME::_der_to_cert' => sub { "PEM: $_[0]" });
  my $b64 = Mock::MonkeyPatch->patch('Mojo::ACME::encode_base64url' => sub { "B64: $_[0]" });
  my $gen_csr = Mock::MonkeyPatch->patch('Mojo::ACME::generate_csr' => sub { shift; "CSR: @_" });

  subtest 'success' => sub {
    $body = 'cert';
    $status = 200;
    my $expect = {
      resource => 'new-cert',
      csr => 'B64: DER: CSR: example.com',
    };
    my $got = $acme->get_cert('example.com');
    is_deeply $gen_csr->method_arguments, ['example.com'], 'generate_csr got expected arguments';
    is_deeply $json, $expect, 'acme service got expected request';
    is $got, 'PEM: cert', 'got expected certificate';
  };

  #subtest 'fail' => sub {
    #$status = 500;

  #};
};

done_testing;


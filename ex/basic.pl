use Mojolicious::Lite;

#app->config(acme => {});

plugin 'ACME';

app->start;


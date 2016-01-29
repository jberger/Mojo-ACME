use Mojolicious::Lite;

use FindBin;
BEGIN { unshift @INC, "$FindBin::Bin/../lib" }

#app->config(acme => {});

plugin 'ACME';

app->start;


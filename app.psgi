use Plack::Request;
use Data::Dumper;
use Template;

my $app = sub {
    my $req = Plack::Request->new(shift);
    my $tt = Template->new({
        INCLUDE_PATH => '/opt/ciphron/kappa/',
	RELATIVE => 1
    });
    my $out;
    my $body;

    my $params = $req->query_parameters;
    
    my @urls = $params->get_all('u');

    if (@urls == 0) {
       $tt->process('templates/enc.tt', {},
                    \$body) or die $tt->error;
    }
    elsif (@urls > 1 || length($urls[0]) == 0 || length($urls[0]) > 2000 ||
               $urls[0] !~ m#^(http)s?://[a-zA-Z.\-/0-9]+$#) {
        # TODO: add more comphrensive regex for matching a URL; above is cursory
        $body = "Invalid request.";
    }
    else {
        my $url = shift @urls;
        $tt->process('templates/dec.tt',
                     { url_ct => $url },
                     \$body) or die $tt->error;
    }

    $tt->process('templates/main.tt',
                 { body => $body },
		 \$out) or die $tt->error;

    return [200, ['Content-Type', 'text/html'], [$out]]
};

#!/usr/bin/perl
use strict;
use YAML;
use YAML::XS;
use Digest::MD5 qw(md5_hex);
use LW2;
use Getopt::Std;

my @apps;
my %opts;

getopts('c:p:d:v', \%opts);

usage() unless $opts{d};

my $domain  = $opts{d};
my $verbose = 0;
$verbose = 1 if $opts{v};
my $path = '';
$path    = $opts{p} if ($opts{p});



opendir(SIGDIR, "/usr/share/doc/kolkata/sigs/") or die $!;
my @filenames = grep {
     /\.yml$/
      && -f "/usr/share/doc/kolkata/sigs/$_"
} readdir(SIGDIR);

my $i = 0;

foreach my $file (@filenames) {
    $apps[$i] = YAML::XS::LoadFile("/usr/share/doc/kolkata/sigs/$file");
    $i++;
}


foreach my $app (@apps) {
    print "Downloading " . $path . $app->{'config'}->{'check_file'} . " to check for " . $app->{'config'}->{'app_name'} . "\n";
    my $contents = download($path . $app->{'config'}->{'check_file'}, $domain);    
    my $target_md5 = md5_hex($contents);
    foreach my $sig (keys %{$app->{'sigs'}}) {
        print "Comparing $target_md5 with " . $app->{'sigs'}->{$sig} . " for " . $app->{'config'}->{'app_name'} . " " . $sig . " detection.\n" if ($verbose > 0);
        die($app->{'config'}->{'app_name'} . " version " . $sig ."\n") if ($app->{'sigs'}->{$sig} eq $target_md5);
    }
}

sub usage {
    print "kolkata.pl -d domain.tld [-v -p [remote_path_to_web_application]]\n";
    exit(0);
}

sub download
{
    my $uri = shift;
    my $try = 5;
    my $host = shift;
    my %request;
    my %response;
    LW2::http_init_request(\%request);
    $request{'whisker'}->{'method'} = "GET";
    $request{'whisker'}->{'host'} = $host;
    $request{'whisker'}->{'uri'} = $uri;
    $request{'whisker'}->{'encode_anti_ids'} = 9;
    $request{'User-Agent'} = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10";
    LW2::http_fixup_request(\%request);
    if(LW2::http_do_request(\%request, \%response)) {
        if($try < 5) {
            print "Failed to fetch $uri on try $try. Retrying...\n";
            return undef if(!download($uri, $try++));
        }
        print "Failed to fetch $uri.\n";
        return undef;
    } else {
        return ($response{'whisker'}->{'data'}, $response{'whisker'}->{'data'});
    }
}

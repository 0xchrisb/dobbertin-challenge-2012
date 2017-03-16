#!/usr/bin/perl
use MIME::Base64;
use LWP::UserAgent;
use HTTP::Request::Common;
$|++;
my $ua = LWP::UserAgent -> new;
$ua->agent('Apache-HttpClient/4.2.1 (java 1.5)');
# u should read 
#http://www.emsec.rub.de/media/crypto/attachments/files/2011/03/chen.pdf
#http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
#
my $asymkey = "ZBnPlwONWHxGDrtCxxopS4y4SrMZIAhUg3HI+SbLMxfPVRPW8yunejrkmfSLO1H/0tOx4ssggygHjG7sUfxL8A==";
my $cipher = decode_base64("i2vygn2vqFpsmep3etrD5Yh5xLP9xYhJdvn63WmHEPYChA==");
my $c1 = substr($cipher,0,16);
my $iv = decode_base64("yv66vvrO263eyviI")."\x00\x00\x00\x02";
$iv = $iv ^ ("\x10"x16);

my $header = encode_base64('{"alg":"RSA_OAEP","iv":"'.encode_base64($iv,'').'","typ":"JWT","enc":"A128CBC"}','');
my $header2 = encode_base64('{"alg":"RSA_OAEP","iv":"'.encode_base64($iv^("\x01".("\x00"x15)),'').'","typ":"JWT","enc":"A128CBC"}','');

for(my $i=1;$i<10000;$i++) {
	my $plain = '{"My PIN:":"'.$i;
	my $res = $ua->request(POST "http://cryptochallenge.nds.rub.de:50080/service",
				Content_Type => 'text/plain; charset=ISO-8859-1',
				"Content"     => "$header.\n$asymkey.\n".encode_base64($plain^$c1,'')."."
	);
	my $source = $res -> content;
	if($source!~/Couldn't decrypt: pad block corrupted/) { #first should be correct
		my $res = $ua->request(POST "http://cryptochallenge.nds.rub.de:50080/service",
		Content_Type => 'text/plain; charset=ISO-8859-1',
		"Content"     => "$header2.\n$asymkey.\n".encode_base64($plain^$c1,'')."."
		);
		my $source = $res -> content;
		print "The PIN is: ".$i."\n" if($source=~/Couldn't decrypt: pad block corrupted/); #second should be incorrect
	}
}

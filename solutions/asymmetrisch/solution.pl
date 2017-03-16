#!/usr/bin/perl
use MIME::Base64;
use LWP::UserAgent;
use HTTP::Request::Common;
use bignum(p=>-10);
use String::HexConvert ':all';
use Crypt::RSA::ES::OAEP;
use strict;
use warnings;
$|++;
my $ua = LWP::UserAgent -> new;
$ua->agent('Apache-HttpClient/4.2.1 (java 1.5)');


my $header = "eyJhbGciOiJSU0ExXzUiLCJpdiI6Inl2NjZ2dnJPMjYzZXl2aUkiLCJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIn0=";
my $asymkey = decode_base64("ZBnPlwONWHxGDrtCxxopS4y4SrMZIAhUg3HI+SbLMxfPVRPW8yunejrkmfSLO1H/0tOx4ssggygHjG7sUfxL8A==");
my $cipher = "i2vygn2vqFpsmep3etrD5Yh5xLP9xYhJdvn63WmHEPYChA==";
my $e = 0x10001;
my $n = 0x008fed3203078bba9fd9a8046da63205afde44a238e03b036c0f1d601415ec3c88c0e9fa82e4f1294c44b03f96a1a51f88a03ef9d36d840658a0a932951ba81081;



$asymkey = hex("6419cf97038d587c460ebb42c71a294b8cb84ab3192008548371c8f926cb3317cf5513d6f32ba77a3ae499f48b3b51ffd2d3b1e2cb208328078c6eec51fc4bf0");
my $B = 2**(8*(64-1));
my $isconform = 0;

#Schritt 1
print "start step 1: ... ";
my $f_1 = 2;
while(!$isconform == 0)  {
	my $tmpasymkey = (squareAndMultiply(sprintf("%b",$e),$f_1,$n) * $asymkey) % $n;
	$tmpasymkey = substr($tmpasymkey -> as_hex(),2,length($tmpasymkey->as_hex)-2);
	$tmpasymkey = hex_to_ascii($tmpasymkey);
	$tmpasymkey = encode_base64($tmpasymkey,'');
	my $res = $ua->request(POST "http://cryptochallenge.nds.rub.de:50080/service",
					Content_Type => 'text/plain; charset=ISO-8859-1',
					"Content"     => "$header.\n$tmpasymkey.\n$cipher."
	);
	my $source = $res -> content;
	$isconform = 1 if($source !~ /Couldn't decrypt: (Data must start with zero|Message is larger than modulus)/);
	$f_1 = $f_1*2;
}


#Schritt 2
$f_1 = ($f_1 / 2)->bfround(0);
print "f_1 : $f_1\n";
print "start step 2: ... ";

my $f_2 = (((($n+$B)/$B) - ((($n+$B)/$B)% 1))->bfround(0) * ($f_1)+1)->bfround(0); #check this later
$isconform = 1;
while($isconform == 1) {

	my $tmpasymkey = (squareAndMultiply(sprintf("%b",$e),$f_2,$n) * $asymkey) % $n;
	$tmpasymkey = substr($tmpasymkey -> as_hex(),2,length($tmpasymkey->as_hex)-2);
	$tmpasymkey = hex_to_ascii($tmpasymkey);
	$tmpasymkey = encode_base64($tmpasymkey,'');
	my $res = $ua->request(POST "http://cryptochallenge.nds.rub.de:50080/service",
						Content_Type => 'text/plain; charset=ISO-8859-1',
						"Content"     => "$header.\n$tmpasymkey.\n$cipher."
	);
	my $source = $res -> content;
	$isconform = 0 if($source !~ /Couldn't decrypt: (Data must start with zero|Message is larger than modulus)/);
	$f_2 = Math::BigInt->new($f_2+$f_1);
	
}
$f_2 = Math::BigInt->new($f_2-1);
print $f_2."\n";

print "start step 3: ... ";
my $m_min = (($n/$f_2-1)->bceil()->bfround(0)+1);
my $m_max = (((($n+$B)/$f_2) - ((($n+$B)/$f_2) % 1))->bfround(0));

my $x = 0;
while($m_min!=$m_max) {
	my $f_tmp = (((2*$B)/($m_max - $m_min->bfround(-5)->bceil())) - (((2*$B)/($m_max - $m_min->bfround(-5)->bceil())% 1) ))->bfround(-5)->bceil();
	my $i = ((($f_tmp * $m_min) / $n) - ((($f_tmp * $m_min) / $n)%1))->bfround(-5)->bceil();
	my $f_3 = (($i*$n)/($m_min->bceil()))->bceil();


	my $tmpasymkey = Math::BigInt->new((squareAndMultiply(sprintf("%b",$e),$f_3,$n) * $asymkey) % $n);
	$tmpasymkey = substr($tmpasymkey -> as_hex(),2,length($tmpasymkey->as_hex)-2);
	$tmpasymkey = "0".$tmpasymkey if(length($tmpasymkey)%2 != 0);
	$tmpasymkey = hex_to_ascii($tmpasymkey);
	$tmpasymkey = encode_base64($tmpasymkey,'');
	my $res = $ua->request(POST "http://cryptochallenge.nds.rub.de:50080/service",
					Content_Type => 'text/plain; charset=ISO-8859-1',
					"Content"     => "$header.\n$tmpasymkey.\n$cipher."
	);
	my $source = $res -> content;

	if($source !~ /Couldn't decrypt: (Data must start with zero|Message is larger than modulus)/) {
		$m_max = ((($i*$n+$B)/$f_3->bfround(-5)->bceil()) - ((($i*$n+$B)/$f_3->bceil())%1));
	} else {
		$m_min = (($i*$n+$B)/$f_3)->bfround(-3)->bceil();
	}
#uncomment for debug ;)	
#	print "=====================\nm_min: $m_min\nm_max: $m_max\nf_3  : $f_3\nCount: $x\n";
	$x++;
}
print "got padded m\n";
print "unpadding m ...\n";

use Crypt::RSA::DataFormat qw(bitsize os2ip i2osp octet_xor octet_len);
use Digest::SHA1           qw(sha1);
my $padded_message = $m_min->bfround(0)->bceil();
my $key = decode(i2osp($padded_message,64-1));
print "got the secret key: ".$key."\n";


##oaep decode function
sub mgf1 {
	my ($seed, $l) = @_;
	my $hlen = 20;  my ($T, $i) = ("",0);
	while ($i <= $l) { 
		my $C = i2osp (int($i), 4);
		$T .= sha1("$seed$C");
		$i += 1; #original in Crypt::RSA::DataFormat in $i += $hlen; but this should be wrong!?
    	}
	my ($output) = unpack "a$l", $T;
	return $output;
}

sub decode {
	my $em = shift;
	my $hlen = 20;
	my $P = "";

	my $maskedseed = substr $em, 0, $hlen; 
	my $maskeddb = substr $em, $hlen; 
	my $seedmask = mgf1($maskeddb, $hlen);
	my $seed = octet_xor($maskedseed, $seedmask);
	my $dbmask = mgf1($seed, length($em) - $hlen);
	my $db = octet_xor ($maskeddb, $dbmask); 
	my $phash = sha1($P); 

	my $phashorig = substr($db, 0, $hlen);
	my $i = 0;

	while((($hlen+$i)<length($db)) && (substr($db,$hlen+$i,1) eq "\x00")) {
		$i++;
	}
	my $um = (substr($db,($hlen+$i+1)));
	$um =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
	return $um;
}

sub squareAndMultiply {
	my ($a, $alpha, $p) = @_;
	
	my $lZ = $alpha;
	my @e = split(//,$a);
	
	for(my $i=1; $i<@e;$i++) {
		$lZ = ($lZ * $lZ) % $p;
		$lZ = ($lZ * $alpha) % $p if($e[$i] eq "1");
	}
	return $lZ;
}


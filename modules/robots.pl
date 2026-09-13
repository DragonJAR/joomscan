#start robots.txt module
dprint("Checking robots.txt existing");
$response=$ua->get("$target/robots.txt");
my $headers  = $response->headers();
my $content_type =$headers->content_type();
if ($response->status_line =~ /200/g and $content_type =~ /text\/plain/g) {
	$source=$response->decoded_content;
	my @lines = split /\n/, $source;
	$probot="";
	foreach my $line( @lines ) { 
		if($line =~ /^\s*(?:dis)?allow\s*:\s*(\S+)/i){
			my $between = $1;
			my $slash = ($between =~ /^\//) ? "" : "/";
			$probot .= "$target$slash$between\n";
		}
	}
	tprint("robots.txt is found\npath : $target/robots.txt \n\nInteresting path found from robots.txt\n$probot");
}else{
	fprint("robots.txt is not found");
}
#end robots.txt module
dprint("Checking user registration");
my $reg_res = $ua->get("$target/index.php?option=com_users&view=registration");
my $source = defined $reg_res ? $reg_res->decoded_content : "";
$source = "" unless defined $source;

if ($source =~ /registration\.register/i or $source =~ /jform_password2/i or $source =~ /jform_email2/i) {
	tprint("registration is enabled\n$target/index.php?option=com_users&view=registration");
} else {
	fprint("user registration is disabled or inaccessible");
}
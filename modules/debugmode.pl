my ($dm_code, $dm_body) = probe_get("");
$source = $dm_body;
if ($source =~ /Joomla\! Debug Console/g or $source =~ /xdebug\.org\/docs\/all_settings/g) {
	dprint("Checking Debug Mode status");
	tprint("Debug mode Enabled : $target/");
} else {
	dprint("Checking Debug Mode status");
	fprint("Debug mode is not enabled");
}

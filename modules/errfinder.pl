#start Checking common logs
dprint("Finding common log files name");
my $ertf=0;
@error = ('error.log','error_log','php-scripts.log','php.errors','php5-fpm.log','php_errors.log','debug.log','security.txt','.well-known/security.txt');
do "$mepath/core/lib.pl";

foreach my $er (@error){
    next unless probe_head_is_file($er);
    tprint("$er path :  $target/$er\n");
    $ertf=1;
}
if($ertf==0) {
    fprint("error log is not found");
}
#end Checking common logs
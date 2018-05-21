# wp-cleaner 
_By Kim Schulz <kim@schulz.dk>_

Simple cleanup/scanner tool for wordpress installations that have been infected


simply add to your path and then run the command in the root of your wordpress installation.
Lines in the output starting with :: will show what pattern the script is currently looking for.

All files possible infected with be listed. It is recommended to check every one of them 
as there can be "false positives". 
If all files are backdoor files (new files unrelated to wordpress itself) then you can simply 
run the script again with --delete as argument. 

## Warning
It is your own fault if this script causes any damage by deleting important files in your wordpress
installation. So make sure to make a backup before starting. 

## changelist
v0.3:
 * added extra scanners for some of the new crypto mining malware for WP. 
v0.2:
 * cleanup and fix --delete to work on all platforms. 

v0.1:
 * Initial version

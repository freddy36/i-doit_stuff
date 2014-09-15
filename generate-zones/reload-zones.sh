#!/bin/bash

# Example how to use the script

#Example $ZONEFILE:
#@       IN      SOA     ns1.example.com. hostmaster.example.com. (
#                        2014091200 ; serial number
#[SNIP]
#
#$INCLUDE /var/cache/bind/example.com.zone.idoit
#
#; custom records (CNAMES/MX/TXT/...) not handled by i-doit
#
#[SNIP]
#;EOF - don't remove

ZONEFILE="/var/cache/bind/example.com.zone"
VERIFICATION_STR="www\s*A\s*192.168.0.100"
IDOIT_ARGS="--url=https://i-doit.example.com --api_key=SecureSecret --zone=example.com --exclude=.lab.example.com --report_id=122"


echo retrieving hostnames from idoit
/usr/local/bin/generate-zones-idoit.py $IDOIT_ARGS > "$ZONEFILE.idoit.new"
echo i-doit changes:
diff -Naur "$ZONEFILE.idoit" "$ZONEFILE.idoit.new"

if ! grep -q "^$VERIFICATION_STR$" "$ZONEFILE.idoit.new"
then
	echo "idoit zone verification failed"
	exit 1;
fi

cp "$ZONEFILE.idoit" "$ZONEFILE.idoit.old"
mv "$ZONEFILE.idoit.new" "$ZONEFILE.idoit"


# update serial (current date or old serial + 1)
echo updating serial number
sed -r "$ZONEFILE" -e "s/^(\s*)([0-9]{10})(\s*;\s*serial.*)$/d=\$(date "+%Y%m%d00"); snold=\$((\2+1)); sn=\$((\$d>\$snold?\$d:\$snold)); echo \"\1\$sn\3\"/ge" > "$ZONEFILE.tmp"

if ! grep -q ';EOF' "$ZONEFILE.tmp"
then
	echo "serial number increase failed"
	exit 2;
fi
mv "$ZONEFILE.tmp" "$ZONEFILE"
rndc reload

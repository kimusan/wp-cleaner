#!/bin/bash
# WORDPRESS CLEANER
# By Kim Schulz <kim@schulz.dk>
# Version 0.2
# github.com/kimusan/wp-cleaner
FOLDER=.
if [ "$1" == "--delete" ]; then
	DELETE=" | tr \"\\n\" \"\\000\" | xargs -0 rm -f"
else
	DELETE=""
fi

echo " :: Checking for \"FilesMan\":"
sh -c "grep -rnwl ${FOLDER} -e \"FilesMan\" ${DELETE}"
echo " :: Checking for \"base64_decode\";return\":";
sh -c "grep -rnwl ${FOLDER} -e \"\\\"base64_decode\\\";return\" ${DELETE}"
echo " :: Checking for \"; \$GLOBALS\":";
sh -c "grep -rnwl ${FOLDER} -e \"; \\\$GLOBALSi\" ${DELETE}"
echo " :: Checking for \"<?php \${\"\":";
sh -c "grep -rnwl ${FOLDER} -e \"<?php \\\${\" ${DELETE}"
echo " :: Checking for \"<?php \$array = array(\":";
sh -c "grep -lrnw ${FOLDER} -e \"<?php \\\$array = array(\" ${DELETE}"
echo " :: Checking for \"mail(stripslashes(\":";
sh -c "grep -lrnw ${FOLDER} -e \"mail(stripslashes(\" ${DELETE}"
echo " :: Checking for \"<?php @array_diff_ukey(\": ";
sh -c "grep -lrnw ${FOLDER} -e \"<?php @array_diff_ukey(\" ${DELETE}"
echo " :: Checking for \"\$_REQUEST[chr(\":";
sh -c "grep -lrnw ${FOLDER} -e \"\\\$_REQUEST\[chr(\" ${DELETE}"
echo " :: Checking for \"<?php \$GLOBALS[\": ";
sh -c "grep -lrnw ${FOLDER} -e \"<?php \\\$GLOBALS\[\" ${DELETE}"
echo " :: Checking for \"eval(\$\{\": ";
sh -c "grep -lrnw ${FOLDER} -e \"eval(\\\${\" ${DELETE}"
echo " :: Checking for \"isset(\${\":";
sh -c "grep -lrnw ${FOLDER} -e \"isset(\\\${\" ${DELETE}"

echo " :: Checking for \"PhpReverseProxy\": ";
sh -c "grep -lrnw ${FOLDER} -e \"PhpReverseProxy\" ${DELETE}"
echo " :: Checking for \"str_rot13\":";
sh -c "grep -lrnw ${FOLDER} -e \"str_rot13(\" ${DELETE}"
echo " :: Checking for \"@set_time_limit(0);\": ";
sh -c "grep -lrnw ${FOLDER} -e \"@set_time_limit(0);\" ${DELETE}"
echo " :: Checking for \"strripos(@sha1(\": ";
sh -c "grep -lrnw ${FOLDER} -e \"strripos(@sha1(\" ${DELETE}"
echo " :: Checking for \" @assert(\":";
sh -c "grep -lrnw ${FOLDER} -e \"@assert(\" ${DELETE}"
echo " :: Checking for \"made-in-china.com\":";
sh -c "grep -lrnw ${FOLDER} -e \"made-in-china.com\" ${DELETE}"

echo " :: Checking for \"trim(curl_exec(\$ch))\":";
sh -c "grep -lrnw ${FOLDER} -e \"trim(curl_exec(\\\$ch))\" ${DELETE}"


echo " :: Checking for \"function.*for.*strlen.*isset\": ";
sh -c "egrep -Rl \"function.*for.*strlen.*isset\" ${FOLDER} ${DELETE}"

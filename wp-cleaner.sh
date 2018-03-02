#!/bin/bash

#
#
# WORDPRESS BASH SCRIPT TO CLEAN BACKDOOR FILES
#
#
FOLDER=.
if [ "$1" == "--delete" ]; then
	DELETE=" | tr \"\\n\" \"\\000\" | xargs -0 rm -f"
else
	DELETE=""
fi

echo " :: FilesMan"
sh -c "grep -rnwl ${FOLDER} -e \"FilesMan\" ${DELETE}"
echo " :: \"base64_decode\";return > ";
sh -c "grep -rnwl ${FOLDER} -e \"\\\"base64_decode\\\";return\" ${DELETE}"
echo " :: ; \$GLOBALS > ";
sh -c "grep -rnwl ${FOLDER} -e \"; \\\$GLOBALSi\" ${DELETE}"
echo " :: <?php \${\" > ";
sh -c "grep -rnwl ${FOLDER} -e \"<?php \\\${\" ${DELETE}"
echo " :: <?php \$array = array( > ";
sh -c "grep -lrnw ${FOLDER} -e \"<?php \\\$array = array(\" ${DELETE}"
echo " :: mail(stripslashes( > ";
sh -c "grep -lrnw ${FOLDER} -e \"mail(stripslashes(\" ${DELETE}"
echo " :: <?php @array_diff_ukey( > ";
sh -c "grep -lrnw ${FOLDER} -e \"<?php @array_diff_ukey(\" ${DELETE}"
echo " :: \$_REQUEST[chr( > ";
sh -c "grep -lrnw ${FOLDER} -e \"\\\$_REQUEST\[chr(\" ${DELETE}"
echo " :: <?php \$GLOBALS[ > ";
sh -c "grep -lrnw ${FOLDER} -e \"<?php \\\$GLOBALS\[\" ${DELETE}"
echo " :: eval(\$\{ > ";
sh -c "grep -lrnw ${FOLDER} -e \"eval(\\\${\" ${DELETE}"
echo " :: isset(\${ > ";
sh -c "grep -lrnw ${FOLDER} -e \"isset(\\\${\" ${DELETE}"

echo " :: PhpReverseProxy > ";
sh -c "grep -lrnw ${FOLDER} -e \"PhpReverseProxy\" ${DELETE}"
echo " :: str_rot13 > ";
sh -c "grep -lrnw ${FOLDER} -e \"str_rot13(\" ${DELETE}"
echo " :: @set_time_limit(0); > ";
sh -c "grep -lrnw ${FOLDER} -e \"@set_time_limit(0);\" ${DELETE}"
echo " :: strripos(@sha1( > ";
sh -c "grep -lrnw ${FOLDER} -e \"strripos(@sha1(\" ${DELETE}"
echo " :: @assert( >";
sh -c "grep -lrnw ${FOLDER} -e \"@assert(\" ${DELETE}"
echo " :: made-in-china.com >";
sh -c "grep -lrnw ${FOLDER} -e \"made-in-china.com\" ${DELETE}"

echo " :: trim(curl_exec(\$ch)) >";
sh -c "grep -lrnw ${FOLDER} -e \"trim(curl_exec(\\\$ch))\" ${DELETE}"


echo " :: function.*for.*strlen.*isset > ";
sh -c "egrep -Rl \"function.*for.*strlen.*isset\" ${FOLDER} ${DELETE}"

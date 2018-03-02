#!/bin/bash

#
#
# WORDPRESS BASH SCRIPT TO CLEAN BACKDOOR FILES
#
#
FOLDER=.
if [ "$1" == "--delete" ]; then
	DELETE=" | tr \"\\n\" \"\\000\" | xargs -0 rm"
else
	DELETE=""
fi

echo " :: FilesMan"
grep -rnw ${FOLDER} -e "FilesMan" | cut -d":" -f1 ${DELETE}
echo " :: \"base64_decode\";return > ";
grep -rnw ${FOLDER} -e "\"base64_decode\";return" | cut -d":" -f1 ${DELETE}
echo " :: ; \$GLOBALS > ";
grep -rnw ${FOLDER} -e "; \$GLOBALS" | cut -d":" -f1 ${DELETE}
echo " :: <?php \${\" > ";
grep -rnw ${FOLDER} -e "<?php \${" | cut -d":" -f1 ${DELETE}

#ssh -i ${AWS_KEYFILE} ubuntu@${DOMAIN} "sudo grep -rnw ${FOLDER} -e 'return base64_decode(' | cut -d\":\" -f1; exit"

echo " :: <?php \$array = array( > ";
grep -rnw ${FOLDER} -e "<?php \$array = array(" | cut -d":" -f1 ${DELETE}
echo " :: mail(stripslashes( > ";
grep -rnw ${FOLDER} -e "mail(stripslashes(" | cut -d":" -f1 ${DELETE}
echo " :: <?php @array_diff_ukey( > ";
grep -rnw ${FOLDER} -e "<?php @array_diff_ukey(" | cut -d":" -f1 ${DELETE}
echo " :: \$_REQUEST[chr( > ";
grep -rnw ${FOLDER} -e "\$_REQUEST\[chr(" | cut -d":" -f1 ${DELETE}
echo " :: <?php \$GLOBALS[ > ";
grep -rnw ${FOLDER} -e "<?php \$GLOBALS\[" | cut -d":" -f1 ${DELETE}

# New backdoors
echo " :: eval(\$\{ > ";
grep -rnw ${FOLDER} -e "eval(\${" | cut -d":" -f1 ${DELETE}
echo " :: isset(\${ > ";
grep -rnw ${FOLDER} -e "isset(\${" | cut -d":" -f1 ${DELETE}

echo " :: PhpReverseProxy > ";
grep -rnw ${FOLDER} -e "PhpReverseProxy" | cut -d":" -f1 ${DELETE}
echo " :: str_rot13 > ";
grep -rnw ${FOLDER} -e "str_rot13(" | cut -d":" -f1 ${DELETE}
echo " :: @set_time_limit(0); > ";
grep -rnw ${FOLDER} -e "@set_time_limit(0);" | cut -d":" -f1 ${DELETE}
echo " :: strripos(@sha1( > ";
grep -rnw ${FOLDER} -e "strripos(@sha1(" | cut -d":" -f1 ${DELETE}
echo " :: @assert( >";
grep -rnw ${FOLDER} -e "@assert(" | cut -d":" -f1 ${DELETE}
echo " :: made-in-china.com >";
grep -rnw ${FOLDER} -e "made-in-china.com" | cut -d":" -f1 ${DELETE}

echo " :: trim(curl_exec(\$ch)) >";
grep -rnw ${FOLDER} -e "trim(curl_exec(\$ch))" | cut -d":" -f1 ${DELETE}


echo " :: function.*for.*strlen.*isset > ";
egrep -Rl \"function.*for.*strlen.*isset\" ${FOLDER} ${DELETE}

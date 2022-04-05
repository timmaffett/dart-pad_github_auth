# execute this script from root directory with
# `tool/make_localhost_certs`    command
# openssl must be installed
#
# Details: https://www.section.io/engineering-education/how-to-get-ssl-https-for-localhost/
RED='\033[0;31m'
NC='\033[0m' # No Color
# IMPORTANT!
printf "${RED}IMPORTANT!${NC}\n"
printf "bin/server.dart assumes '${RED}dartdart${NC}' is used for all pass phrases\n"
# bin/server.dart assumes 'dartdart' is used for all pass phrases
# 
cd make_localhost_certs/CA
# creating CA
openssl genrsa -out CA.key -des3 2048
openssl req -x509 -sha256 -new -nodes -days 3650 -key CA.key -out CA.pem
# create localhost
cd localhost
openssl genrsa -out localhost.key -des3 2048
openssl req -new -key localhost.key -out localhost.csr
openssl x509 -req -in localhost.csr -CA ../CA.pem -CAkey ../CA.key -CAcreateserial -days 3650 -sha256 -extfile localhost.ext -out localhost.crt
# concat key, cert and CA.pem to make localhost.pem keychain
cat localhost.key localhost.crt ../CA.pem >localhost.pem
# You will need to go to your browser settings 'manager certificates'
# and add CA.PEM to your trusted certificate authorities
# returning to root
cd ../../..
# renaming directory so it is excluded from docker and git
#ren make_localhost_certs certificates
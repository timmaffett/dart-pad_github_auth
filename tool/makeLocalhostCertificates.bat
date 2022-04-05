rem execute this script from root directory with
rem `tool\make_localhost_certs`    command
rem openssl must be installed
rem
rem Details: https://www.section.io/engineering-education/how-to-get-ssl-https-for-localhost/
rem IMPORTANT!
rem bin\server.dart assumes 'dartdart' is used for all passkeys
rem 
cd make_localhost_certs\CA
rem creating CA
openssl genrsa -out CA.key -des3 2048
openssl req -x509 -sha256 -new -nodes -days 3650 -key CA.key -out CA.pem
rem create localhost
cd localhost
openssl genrsa -out localhost.key -des3 2048
openssl req -new -key localhost.key -out localhost.csr
openssl x509 -req -in localhost.csr -CA ../CA.pem -CAkey ../CA.key -CAcreateserial -days 3650 -sha256 -extfile localhost.ext -out localhost.crt
rem concat key, cert and CA.pem to make localhost.pem keychain
copy /b localhost.key+localhost.crt+..\CA.pem localhost.pem
rem You will need to go to your browser settings 'manager certificates'
rem and add CA.PEM to your trusted certificate authorities
rem returning to root
cd ..\..\..
rem renaming directory so it is excluded from docker and git
ren make_localhost_certs certificates
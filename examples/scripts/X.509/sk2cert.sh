#./bin/bash
#The script expects an input like:
# ./sk2cert.sh sk.pem user@gmail.com CAsk.pem CA.pem csr.crt
# sk.pem stores a TLCS secret key and the script writes the corresponding certificate in user@gmail.com.p12 (for the pkcs12 format) and user@gmail.com.crt (for the PEM format)
# The certificate is signed by CA with secret key stored in the file CAsk.pem whose certificate is stored in the file CA.pem. Theese two files are assumed to have been computed by the script setupCA.sh
# We use the CSR created by pk2cert.sh stored in user@gmail.com.csr.crt
if [ "$#" -ne 4 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 sk.pem user@gmail.com CAsk.pem CA.pem"
	exit
fi


openssl x509 -req -days 365 -in $2.csr.crt -signkey $1 -out $2.sk.crt -CA $4 -CAkey $3 -CAcreateserial
openssl pkcs12 -export -in $2.sk.crt -inkey $1 -out $2.p12


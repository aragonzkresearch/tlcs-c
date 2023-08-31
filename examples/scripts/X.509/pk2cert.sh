#./bin/bash
#The script expects an input like:
# ./pk2cert.sh pk.pem user@gmail.com CAsk.pem CA.pem 
# pk.pem stores a TLCS public key and the script writes the corresponding certificate in user@gmailcom.crt
# The certificate is signed by CA with secret key stored in the file CAsk.pem whose certificate is stored in the file CA.pem. Theese two files are assumed to have been computed by the script setupCA.sh
# user@gmail.com.csr.crt is the file where we will store the CSR that will be used later from the sk2cert.sh script
if [ "$#" -ne 4 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 pk.pem user@gmail.com CAsk.pem CA.pem"
	exit
fi

#Create a certificate signing request:
../setup.sh tempsk.pem temppk.pem
cp extension_file.conf extension_file_$2.conf
sed -i s/EMAIL/$2/g extension_file_$2.conf
vi extension_file_$2.conf
openssl req -new  -key tempsk.pem -out $2.csr.crt -config extension_file_$2.conf
echo "CSR created"

#Finally we create our timelock.zone.crt certificate.
openssl x509 -req -days 365 -in $2.csr.crt -force_pubkey $1 -out $2.crt -CA $4 -CAkey $3 -CAcreateserial -extfile extension_file_$2.conf -extensions v3_req
echo "Certificate created"
rm temppk.pem
rm tempsk.pem
rm extension_file_$2.conf
# We do not delete the CSR $2.csr.crt. If you need you can send it to a real CA to get a valid certificate. In this case you will not need to set in your system CA.pem as trusted CA's certificate

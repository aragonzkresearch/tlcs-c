#./bin/bash
#The script expects an input like:
# ./setupCA.sh CAsk.pem CA.pem 
# The certificate is signed by CA whose secret key will be stored in the file CAsk.pem and whose certificate will be stored in the file CA.pem 
# The CA key is RSA-based, you can tweak the script to generate it the certificate with ECC or any key you wish
if [ "$#" -ne 2 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 CAsk.pem CA.pem"
	exit
fi

#Create a CA pair of certificate and secret keys.
openssl req -new -x509 -out $2 -nodes
mv privkey.pem $1
echo "CA created"


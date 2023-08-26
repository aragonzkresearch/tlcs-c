#!/bin/bash
#The script expects an input like:
# ./setup.sh sk.pem pk.pem
if [ "$#" -ne 2 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 sk.pem pk.pem"
	exit
fi
# We setup a PK and SK pair.
openssl ecparam -name secp256k1 -genkey -noout -out $1
# derive PK from SK
openssl ec -in $1 -pubout -out $2


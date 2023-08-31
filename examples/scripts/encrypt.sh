#!/bin/bash
# $1 is the name of the file that contain PK, like pk.pem, and $2 the msg, $3 is the file containing the first part of the ciphertext and $4 the file containing the second part of the ciphertext
if [ "$#" -ne 4 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 pk.pem "string to encrypt" ct1 ct2"
	echo "the encrypted ciphertext will consist of a pair written in the files ct1 and ct2"
	exit
fi
# We setup a temporary PK and SK pair
openssl ecparam -name secp256k1 -genkey -noout -out temp_sk.pem
# Extract temporary PK from temporary SK
openssl ec -in temp_sk.pem -pubout -out $3

openssl pkeyutl -derive -inkey temp_sk.pem -peerkey $1 -out temp_dh.bin
echo -n $2 > tmpstr
openssl enc -pbkdf2 -aes256 -base64 -k $(base64 temp_dh.bin) -e -in tmpstr -out $4
rm tmpstr
rm temp_sk.pem
rm temp_dh.bin

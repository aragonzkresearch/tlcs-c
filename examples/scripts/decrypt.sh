#!/bin/bash
# $1 is the name of the file that contain SK, like sk.pem, and $2 the name of the file containg the first part of the ciphertext and $3 the name of the file containing the second part of the ciphertext
if [ "$#" -ne 3 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 sk.pem ct1 ct2"
	echo "the ciphertext consists of a pair written in the files ct1 and ct2. the output is given in the stdout"
	exit
fi


openssl pkeyutl -derive -inkey $1 -peerkey $2 -out temp_dh.bin
openssl enc -pbkdf2 -aes256 -base64 -k $(base64 temp_dh.bin) -d -in $3
rm temp_dh.bin

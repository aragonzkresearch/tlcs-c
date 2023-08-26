#!/bin/bash
# Convert a SK in raw format (as output by the timelock.zone service) into PEM format for secp256k1
if [ "$#" -ne 2 ]; then
	echo "illegal number of parameters"
	echo "Example:"
	echo "$0 "9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7" sk.pem"
	exit
fi
echo 302e0201010420 $1 a00706052b8104000a | xxd -r -p >tmpsk.1
openssl ec -inform d tmpsk.1
openssl ec -inform d <tmpsk.1 >$2
rm tmpsk.1


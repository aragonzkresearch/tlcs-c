#!/bin/bash
rm tmp
echo -ne "714\n1\n" > tmp
rm tmpproof
./bin/prover4blockchain tmpproof <tmp
cat tmpproof
rm tmpproof
rm tmp

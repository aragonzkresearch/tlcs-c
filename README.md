# Time Lock Cryptographic Service (TLCS) based on League of Entropy (a.k.a. drand)
## Overview
The repository provides implementation of TLCS described as Protocol 2 in this [note](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ).
The implementation is based on the [mcl](https://github.com/herumi/mcl/) library By Shigeo Mitsunari/ and openssl.
The TLCS library allows to create public keys for virtually any elliptic curve supported by openssl and in addition the `G1` group of the `BLS12_381` curve.
To use the `G1` group set `-D_CYC_GRP_BLS_G1=1`  in the `Makefile` before installation. Observe that in this case you cannot use the public keys to encrypt with El Gamal because El Gamal is not secure in bilinear groups. If you use the public keys in the `G1` group, you should instead encrypt with hashed El Gamal or Linear encryption.
## Installation
```bash
git clone https://github.com/herumi/mcl.git
cd mcl
make all
cd ..
chmod u+x install.sh
./install.sh
```
## APIs

The APIs can be divided in routines for:
* the prover contained in the file `src/prover.c`
* for the verifier in `src/verifier.c`
* for inversion of the public key in `src/invert.c`
* aggregation of the participants' public keys in `src/aggregate.c` 

## Demo
The source code contains a file * `example/tlcs.c` implementing a demo simulation of a TLCS activity using the routines in the library. 
 The demo is supposed to simulate locally a TLCS protocol consisting of proving, verification, aggregation and inversion phases. 
## Contacts

Vincenzo Iovino (vincenzo@aragon.org)

Aragon ZK Research Team: https://research.aragon.org/

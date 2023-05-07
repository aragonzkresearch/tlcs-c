# Time Lock Cryptographic Service (TLCS) based on League of Entropy (a.k.a. drand)
## Overview
The repository provides implementation of TLCS described as Protocol 2 in this [note](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ).
The implementation is based on the [mcl](https://github.com/herumi/mcl/) library By Shigeo Mitsunari/
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

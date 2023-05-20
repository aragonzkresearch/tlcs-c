# Time Lock Cryptographic Service (TLCS) based on League of Entropy (a.k.a. drand)
## Overview
The repository provides implementation of the TLCS protocol described in this [note](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ).
The implementation is based on the [mcl](https://github.com/herumi/mcl/) library By Shigeo Mitsunari/and openssl.
The TLCS library allows to create public keys for virtually any elliptic curve supported by openssl and in addition the `G1` group of the `BLS12_381` curve and the babyjubjub curve.
To use the `G1` group set `-D_CYC_GRP_BLS_G1=1`  in the `Makefile` before installation or use the corresponding library. Observe that in this case you cannot use the public keys to encrypt with El Gamal because El Gamal is not secure in bilinear groups. If you use the public keys in the `G1` group, you should instead encrypt with hashed El Gamal or Linear encryption. To use RSA set `-D_CYC_GRP_RSA=1` or use the corresponding library. 
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

##  News
* 20-May-2023 Added experimental support for the secret sharing variant.
* 16-May-2023 Added experimental support for babyjubjub ec.
* 14-May-2023 Added support for RSA.
* 07-May-2023 Launch!

## Demo
The source code contains a file * `example/tlcs.c` implementing a demo simulation of a TLCS activity using the routines in the library. 
 The demo is supposed to simulate locally a TLCS protocol consisting of proving, verification, aggregation and inversion phases. 
### Example of usage of the demo
```bash
./bin/demo_prover proof
```
The previous command will simulate a party that creates his public key and proof and writes it to the file named `proof`.
The demo will ask you for which type of curve you want to generate your public key and for a round number `T` of LOE with respect to which you want that the protocol is executed. 
The file is intented to simulate a blockchain activity so if you will re-execute the same command with same file, you will simulate another party who wrote to the blockchain.
Let us suppose we executed the command twice and in each execution we used the same file `proof`, the same curve number (e.g., `714`) and we selected the same input `T`.

Now, the file `proof` contains the public keys and the proofs of two parties. 
```bash
./bin/demo_verifier proof verificationresult
```
The previous command simulates a verifier that reads the fil ``proof`` and writes an array of 0/1 results in the file ``verificationresult``. The i-th element of the array is `1` if the proof of the i-th party is verifid successfully and `0` otherwise.
So, in our example after the execution of the last command, the fil ``verificationresult`` will contain the string ``1 1`` to indicate that both proofs of the two parties were successfully verified.
```bash
./bin/demo_aggregator proof aggregated_pk 1 1
```
The previous commands simulates the aggregation phase of the protocol. The aggregator reads the file `proof` that in our example contains the output of two parties and uses the list `1 1` to know which party computed valid proof (in our example both parties computed valid proofs so the list is `1 1`) and outputs the aggregated public key in the file `aggregated_pk`.

At time `T`, LOE publishes a signature for the time `T` (the link where to get this signature was printed out after executing `demo_prover`).
```bash
./bin/demo_invert proof aggregated_pk 1 1
```
The previous command simulates the inversion phase in which after time `T` we aim at inverting the aggregated public key contained in the file `aggregated_pk`. To this purpose we pass as input to the latter program the file `proof` that contains the public keys of all parties who participated in the protocol and their respective proofs, the aggregate public key file `aggregated_pk` and, in our example, the list of 0/1 values `1 1` to indicate that the file `proof` contains two proofs that are both accepted.
The program will ask for you for the signature of LOE of time `T` and should print out the secret key corresponding to the aggregated public key in the file `aggregated_pk`.

## Contacts

Vincenzo Iovino (vincenzo@aragon.org)

Aragon ZK Research Team: https://research.aragon.org/

## References
Vincenzo Iovino. [How to Build a Time Lock Crypto Service based on League of Entropy](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ), May 2023.

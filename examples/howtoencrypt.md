# How to use our system to encrypt

## Openssl examples
In the files `examples/setup.sh`,  `examples/encrypt.sh` and `examples/decrypt.sh` we provided a complete public key encryption system based on openssl. Precisely, we implement the [Integrated Encryption Sscheme (IES)](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) public key encryption scheme with respect to the curve ``secp256k1`` and using ``aes256`` as symmetric encryption scheme and ``pbkdf2`` as key derivation function.
Let us first show how this system would work in a normal scenario (without using a TLCS system).
(Henceforth, we suppose to be in the directory ``examples``.)


### How encryption works without the TLCS system
```bash
./setup.sh sk.pem pk.pem
```
The last command writes a secret key in the file ``sk.pem`` and a public key in the file ``pk.pem``.
```bash
./encrypt.sh pk.pem "ciao" ct1 ct2
```
The last command encrypts the string "ciao" using the public key computed before and stores the ciphertexts in the pair of files ``ct1`` and ``ct2`` (for technical reasons the full ciphertext consists of a pair of files).

```bash
./decrypt.sh sk.pem ct1 ct2
```
The last command decrypts the ciphertext encoded in the two files ``ct1`` and ``ct2`` computed previously using the secret key ``sk.pem`` compute by ``setup.sh`` and outputs the decrypted message (that should be "ciao" in our example) in the ``stdout``.

### How encryption works with the TLCS system

The flow using the TLCS system would be the following.
Suppose the TLCS system computed a public key ``03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD`` for round number ``R`` with respect to the ``secp256k1`` elliptic curve. The openssl NID identifier for ``secp256k1`` is ``714``.

Then we can run the following command:
```bash
./rawpk2pem 714 03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD > pk.pem
```
The last command takes as input the identifer ``714`` for ``secp256k1`` and the string representing the public key in raw format computed by the TLCS system and computes a public key in PEM format and stores it in the file ``pk.pem``.
Then, we can execute again the following command:

```bash
./encrypt.sh pk.pem "ciao" ct1 ct2
```
Observe that the command is identical as in the execution without the TLCS system.

Now suppose at the time corresponding to round number ``R``, the TLCS system releases a secret key ``9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7``.
We can now run the following command to convert such secret key in raw format into PEM format and stores the result in the file ``sk.pem``:
```bash
./rawskey2pem.sh 9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7 sk.pem
```

We can now run the command:
```bash
./decrypt.sh sk.pem ct1 ct2
```
and we will get the plaintext "ciao"!

Observe that for usage with the TLCS system we do not need the ``setup.sh`` procedure.
## Other frameworks
We will soon show examples on how to use our TLCS system with other libraries and development frameworks. For the moment, observe that the previous keys (both public and secret) are in PEM format and can be used by virtually all crypto libraries.

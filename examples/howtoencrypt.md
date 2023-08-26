# How to use our system to encrypt

## Openssl examples
In the files `examples/setup.sh`,  `examples/encrypt.sh` and `examples/decrypt.sh` we provided a complete encryption system based on openssl.
Let us first show how this system would work in a normal scenario (without using a TLCS system).
(Henceforth, we suppose to be in the directory ``examples``.)

```bash
./setup.sh sk.pem pk.pem
```
The latter writes a secret key in the file ``sk.pem`` and a public key in the file ``pk.pem``.
```bash
./encrypt.sh pk.pem "ciao" ct1 ct2
```
The latter encrypts the string "ciao" using the public key computed before and stores the ciphertexts in the pair of files ``ct1`` and ``ct2`` (for technical reasons the full ciphertext consists of a pair of files).

```bash
./decrypt.sh sk.pem ct1 ct2
```
The latter decrypts the ciphertext encoded in the two files ``ct1`` and ``ct2`` computed previously using the secret key ``sk.pem`` compute by ``setup.sh`` and outputs the corresponding message in the ``stdout``.

The flow using the TLCS system would be the following.
Suppose the TLCS system computed a public key ``03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD`` for the ``secp256k1`` whose openssl NID identifier is ``714``.

Then we can run the following command:
```bash
./rawpk2pem 714 03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD > pk.pem
```
The last command computes a public key in PEM format and stores it in the file ``pk.pem``.
Then, we can execute again the following command:

```bash
./encrypt.sh pk.pem "ciao" ct1 ct2
```
Observe that the command is identical as in the execution without the TLCS system.

Now suppose at a certain time the TLCS system releases a secret key ``9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7``.
We can now run the following command to convert such secret key in raw format into PEM format and stores the result in the file ``sk.pem``:
```bash
./rawskey2pem.sh 9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7 sk.pem
```

We can now run the command:
```bash
./decrypt.sh sk.pem ct1 ct2
```
and we will get the plaintext "ciao"!

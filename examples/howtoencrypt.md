# How to use our system to encrypt

## Encrypt with Openssl tools and libraries
In the files `examples/scripts/setup.sh`,  `examples/scripts/encrypt.sh` and `examples/scripts/decrypt.sh` we provided a complete public key encryption system based on openssl. Precisely, we implement the [Integrated Encryption Sscheme (IES)](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) public key encryption scheme with respect to the curve ``secp256k1`` and using ``aes256`` as symmetric encryption scheme and ``pbkdf2`` as key derivation function.
Let us first show how this system would work in a normal scenario (without using a TLCS system).
(Henceforth, we suppose to be in the directory ``examples/scripts``.)


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
../rawpk2pem 714 03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD > pk.pem
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

The previous scripts can be also ported in all programming languages in which there are openssl libraries or bindings (C/C++, Rust, etc.).
## Java and Android
We assume the availability of the files  ``pk.pem`` and ``sk.pem`` as computed above.
Unfortunately, the standard Java Crypto Architecture (JCA) may not support elliptic curve cryptography (ECC). However, ECC is usually done using the famous [bouncycastle](https://www.bouncycastle.org/) provider.
Your Java code may not depend at all from the specific provider you use, it will be the JCA to select the best provider that in your system offers ECC but be aware that if you do not have any provider at all that supports ECC, JCA will raise an error.

As an example, in [ECIES.java](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/Java/ECIES.java) we show an implementation of the ECIES public key encryption scheme in Java (it may need the ``bouncycastle`` provider to run successfully) that assumes public key in PEM format and secret key in ``pkcs8`` format.
You can use the public key in PEM format generated using the program ``rawpk2pem`` as shown before.
For the secret key, you can convert the secret key ``sk.pem`` generated before in ``pkcs8`` format as shown in the following command:
```bash
openssl pkcs8 -topk8  -in sk.pem -out sk.pkcs8 -nocrypt
```
With these two files, you can use ``ECIES.java`` in a straightforward way.
The code also works in Android if the right provider (e.g., Bouncycastle) is installed.
You should edit in the code the path to the public key ``pk.pem`` and secret key ``sk.pkcs8``.

## Python
In Python, consider the packages [eciespi](https://pypi.org/project/eciespy/) of the ``PyPi`` library.
You can install it with:
```bash
pip3 install eciespi
```
(Or you can replace ``pip3`` by just ``pip``.)

We will show how to use the command lines tools of the package and we defer to the webpage of the project for examples on how to do it programmatically.
The library and tools supports keys directly in raw format so we can use the TLCS keys in a straightforward way as follows.

Suppose as before that the public key for round ``R`` published by the TLCS system is ``03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD``.

We can run the following commands to encrypt the plaintext "ciao" in the file ``ct``.
```bash
echo 03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD >pk
echo "ciao">plaintext
eciespy -e -k pk <plaintext >ct
```
 Now, suppose that at round ``R`` the service will release the corresponding secret key ``9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7``.
We can then decrypt with the following command:
```bash
echo 9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7 >sk
eciespy -d -k sk <ct
```
and we will get the right plaintext "ciao".

## Javascript, Wasm and modern browsers
We will use the [ecies-wasm](https://github.com/ecies/rs-wasm) package that is the ``wasm`` version of the previous Python library.
We now suppose to be in the directory ``examples``.

```bash
git clone  https://github.com/ecies/rs-wasm
```

We overwrite the example of ``ecies-wasm`` with our file ``example/js/index.js`` that uses the TLCS keys shown in this document and a simple hex to binary conversion function ``fromHexString``.
We now suppose to be in the directory ``example``.

```bash
cp js/index.js rs-wasm/example
```
You can now follow the instructions given [here](https://github.com/ecies/rs-wasm/tree/master/example) to run a server that uses the example (now, our overwritten example) to encrypt and decrypt with respect our TLCS keys.

## Encrypted emails and digital certificates
The issue of creating digital certificates from TLCS public keys is in the fact that you need to create the certificate from a TLCS public key when the corresponding secret key is not available yet.
Standard managament tools for ``X.509`` digital certificates require knowledge of a secret key at time of creation of the certificate (or create the secret key on the fly).

We have been able to exploit the ``force_pubkey`` option in ``openssl`` to bypass this issue.

The flow to use our TLCS system to create timed-certificates is the following.
We now suppose to be in the directory ``examples/scripts/X.509``.

Firstly, we need to create a Certificate Authority (CA) pair that will be used to sign all users' certificates for all rounds.
This is done with the script ``setupCA.sh``:
```bash
./setupCA.sh CAsk.pem CApk.pem
```
The CA's secret key is now in ``CAsk.pem`` and the certificate is in ``CApk.pem``. The command will ask to input the data of the certification authority.

Suppose that Alice wants to send an encrypted message for round ``R`` to Bob whose email address is ``user@gmail.com``.
Suppose that ``T`` is the time corresponding to round ``R``, e.g. ``T`` is equal to ``12/13/2023`` (the time is an exact date in the format ``MM/DD/YYYY``).
We assume the file ``pk.pem`` is created from the public key for round ``R`` as shown [before](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/howtoencrypt.md#openssl-examples).
When the public key ``pk.pem`` for round ``R`` is available, Alice can run the following script:
```bash
./pk2cert.sh pk.pem user@gmail.com CAsk.pem CA.pem 12/13/2023
````
The command will ask Alice to input the data corresponding to the certificate you are creating such as Country, Organization, etc. Specifically Alice can edit this info from a file that will be opened by the script via ``vim`` command (type ``:x`` to exit from ``vim`` when you finish to edit).
The output certificate will be ``user@gmail.com.crt`` and will have validity until ``12/13/2023`` or the time ``T`` you choose.

### Encrypted emails from command line
Now, Alice can encrypt an email with content "ciao" to this recipient with the following command:
```bash
echo "ciao" >msg
openssl cms -encrypt -in msg -out ct.p7m -CAfile CA.pem  -from "youraddress@outlook.com" -to "user@gmail.com" -subject "email to the future" user@gmail.com.crt
```
The encrypted message is stored in the file ``ct.p7m`` and will look like:
```
To: user@gmail.com
From: youraddress@outlook.com
Subject: email to the future
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIBogYJKoZIhvcNAQcDoIIBkzCCAY8CAQIxggFboYIBVwIBA6BRoU8wCQYHKoZI
zj0CAQNCAATo4sQpUGNr1RSdxhhIHQ5/0+DNd9F5PjxjMKQRbL4tazM2JEKSIAaP
E5vo+b6oQugaDiQkHffWvc4Gsi8yPofZMBwGCSuBBRCGSD8AAjAPBgsqhkiG9w0B
CRADBgUAMIHgMIHdMIGwMIGXMQswCQYDVQQGEwJTVTELMAkGA1UECAwCWlUxDDAK
BgNVBAcMA1p1ZzEWMBQGA1UECgwNdGltZWxvY2suem9uZTEWMBQGA1UECwwNdGlt
ZWxvY2suem9uZTEWMBQGA1UEAwwNdGltZWxvY2suem9uZTElMCMGCSqGSIb3DQEJ
ARYWdGltZWxvY2tAdGltZWxvY2suem9uZQIUAyx2y7YY6IzvFpBtuvLDRVX3RwME
KEzRSAuOITUY6eVNsvFoycOSu+WnukyiXziy2EGSgCBUJHIMiboEofkwKwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhIIrIxxjQzB4AImRmqeljdJ08=
```
Alice will send this file ``ct.p7m`` to Bob.

At time ``R``, as shown [before](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/howtoencrypt.md#openssl-examples), Bob can compute the secret key ``sk.pem``.
Bob can now run the following script to decrypt and get the string "ciao":
```bash
openssl cms -decrypt -in ct.p7m -CAfile CA.pem  -inkey sk.pem
```
### Encrypted emails from email clients
Virtually, it should be possible to integrate this with email clients in the following way.
Suppose that Alice wants to send an encrypted message for round ``R`` to Bob whose email address is ``user@gmail.com``.
First, the sender Alice needs to import the corresponding certificate ``user@gmail.com.crt`` as shown before.
Second, after having imported such certificate, Alice also needs to add ``CA.pem`` as trusted root certificate in her email system (or OS) so that the certificate ``user@gmail.com.p12`` looks as coming from a trusted source.
Finally, Alice can use her favourite email client to send an encrypted message to Bob's email address ``user@gmail.com``.

We now suppose to be in the directory ``examples/scripts/X.509``.
In order to be able to decrypt after round ``R``, Bob needs to perform the following operations.
As shown [before](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/howtoencrypt.md#openssl-examples), Bob can compute the secret key ``sk.pem``.
Then, Bob needs to compute the certificate ``user@gmail.com.p12`` output by the following script:
```bash
./sk2cert.sh sk.pem user@gmail.com CAsk.pem CA.pem
````
Bob will be asked to input his own private data that should be equal to the data that Alice used to compute ``user@gmail.com.crt``.
Then, Bob must import such certificate ``user@gmail.com.p12`` in his own email client or OS. The default password Bob should input is ``timelock.zone``. Observe that there is no need for any secure password since after round ``R`` anyone can publicly compute such a certificate.

Finally, after having imported such certificate, Bob also needs to add ``CA.pem`` as trusted root certificate in his email system (or OS) so that the certificate ``user@gmail.com.p12`` looks as coming from a trusted source.

If now Bob opens his email client, he should find the encrypted email unencrypted.

Note that most email clients send as attachment a file ``smime.p7m`` contained the encrypted body of the email.
You can use the following command:
```bash
openssl asn1parse -in smime.p7m -inform der
```
to parse the encrypted message, and one of the fields corresponds to the serial number (S/N) of the Bob's certificates.
The email clients use such information to identify the certificate used to encrypt.
#### Issues
The issue to prevent all this to work inside email clients can be the support for ECC.
We also remark that while `openssl cms`` works, ``openssl smime`` does not. The former supports only recents versions of the S/MIME and its formats could not be supported by all S/MIME softwares.

### Using the so create digital certificates in Java to encrypt
Consider the certificate ``user@gmail.com.crt`` created as above.
We provide a sample Java code [ECIESfromCertificate.java](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/Java/ECIESfromCertificate.java) that works identically to [ECIES.java](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/Java/ECIES.java) except that the public key is taken by the certificate ``user@gmail.com.crt``.
This can be useful in many libraries where the encryption procedure only accepts valid ``X.509`` certificates.
You should edit in the code the path to the certificate ``user@gmail.crt`` and secret key ``sk.pkcs8``.
Observe that for many applications such a certificate could be filled with fake data and containing as only useful information the round ``R`` to which it corresponds.

## Other frameworks
We will soon show examples on how to use our TLCS system with other libraries and development frameworks. For the moment, observe that we showed that the public and secret keys offered by our system can be converted in known formats and so can be used by virtually all crypto libraries.


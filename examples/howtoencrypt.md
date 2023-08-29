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

The previous scripts can be also ported in all programming languages in which there are openssl libraries or bindings (C/C++, Rust, etc.).
## Java and Android
We assume the availability of the files  ``pk.pem`` and ``sk.pem`` as computed above.
Unfortunately, the standard Java Crypto Architecture (JCA) may not support elliptic curve cryptography (ECC). However, ECC is usually done using the famous [bouncycastle](https://www.bouncycastle.org/) provider.
Your Java code may not depend at all from the specific provider you use, it will be the JCA to select the best provider that in your system offers ECC but be aware that if you do not have any provider at all that supports ECC, JCA will raise an error.

As an example, in [ECIES.java](https://github.com/aragonzkresearch/tlcs-c/blob/main/examples/ECIES.java) we show an implementation of the ECIES public key encryption scheme in Java (it may need the ``bouncycastle`` provider to run successfully) that assumes public key in PEM format and secret key in ``pkcs8`` format.
You can use the public key in PEM format generated using the program ``rawpk2pem`` as shown before.
For the secret key, you can convert the secret key ``sk.pem`` generated before in ``pkcs8`` format as shown in the following command:
```bash
openssl pkcs8 -topk8  -in sk.pem -out sk.pkcs8 -nocrypt
```
With these two files, you can use ``ECIES.java`` in a straightforward way.
The code also works in Android if the right provider (e.g., Bouncycastle) is installed.

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

```bash
git clone  https://github.com/ecies/rs-wasm
```

We overwrite the example of ``ecies-wasm`` with our file ``example/index.js`` that uses the TLCS keys shown in this document and a simple hex to binary conversion function ``fromHexString``.
We now suppose to be in the directory ``example``.

```bash
cp index.js rs-wasm/example
```
You can now follow the instructions given [here](https://github.com/ecies/rs-wasm/tree/master/example) to run a server that uses the example (now, our overwritten example) to encrypt and decrypt with respect our TLCS keys.

## Encrypted emails and digital certificates
The issue of creating digital certificates from TLCS public keys is in the fact that when you need to create the certificate from a TLCS public key when the corresponding secret key is not available yet.
Unfortunately, standard managament of certificates requires knowledge of secret key at time of creation of the certificate.

We have been able to exploit the ``force_pubkey`` option in ``openssl`` to bypass this issue.

The process of creating a certificate for the ``user@gmail.com`` is the following.
Firstly, we need to create a Certificate Authority (CA) pair.

This is done with the script ``setupCA.sh``:
```bash
./setupCA.sh CAsk.pem CApk.pem
```
The CA's secret key is now in ``CAsk.pem`` and the certificate is in ``CApk.pem``. The command will ask to input the data of the certification authority.
We assume the file ``pk.pem`` is created from the public key for round ``R`` as shown at the beginning.

Then, when the public key ``pk.pem`` for round ``R`` is available you can run the following script:
```bash
../pk2cert.sh pk.pem user@gmail.com CAsk.pem CA.pem
````
The command will ask you to input the data corresponding to the certificate you are creating such as Country, Organization, etc.
The output certificate will be user@gmail.com.crt.

Notice that we could encode the round ``R`` in one of the certificate fields, in this case each user certificate would be bound to a specific time.
### Encrypted emails from command line
Now, you can encrypt an email with content "ciao" to this recipient with the following command:
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
At time ``R``, as shown at the beginning, we can compute the secret key ``sk.pem``.
You can now run the following script to decrypt and get the string "ciao":
```bash
openssl cms -decrypt -in ct.p7m -CAfile CA.pem  -inkey sk.pem
```
### Encrypted emails from email clients
Virtually, it should be possible to integrate this with email clients by importing the corresponding certificate ``user@gmail.com.crt`` and then using your favourite email client to send emails to address ``user@gmail.com``.

Moreover, the user ``user@gmail.com`` who needs to decrypt after round ``R`` should be able to set as his/her own decryption certificate the file ``user@gmail.com.p12`` output by the following script:
```bash
../sk2cert.sh sk.pem user@gmail.com CAsk.pem CA.pem
````
After having imported such certificate, the user ``user@gmail.com`` also needs to add ``CA.pem`` as trusted root certificate in his/her email system (or OS).

The issue to prevent this to work inside email clients can be the support for ECC.

## Other frameworks
We will soon show examples on how to use our TLCS system with other libraries and development frameworks. For the moment, observe that we showed that the public and secret keys offered by our system can be converted in known formats and so can be used by virtually all crypto libraries.


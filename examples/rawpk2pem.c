#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

void err (const char *label){  // for test; improve for real code
  fprintf (stderr, "Error in %s:\n", label);
  ERR_print_errors_fp (stderr);
  exit (1);
}

int main (int argc, char**argv)
{
  size_t len;
  ERR_load_crypto_strings(); 
  //OPENSSL_add_all_algorithms_noconf(); /* for PKCS#8 */
  if (argc<2){
printf("Usage: %s NID PK\nNID is the identifier of the openssl curve and PK is the public key in raw hex format\n", argv[0]);
exit(1);
 }  
len=strlen(argv[2])/2;
  {	
  unsigned char raw [len]; for( int i = 0; i < len; i++ ){ sscanf(argv[2]+2*i, "%2hhx", raw+i); }

  EC_KEY *eck = EC_KEY_new_by_curve_name(atoi(argv[1])); 
  if( !eck ) err("ECCnewbyname");
  EC_KEY_set_asn1_flag(eck, OPENSSL_EC_NAMED_CURVE); 
  const unsigned char *ptr = raw;
  if( !o2i_ECPublicKey (&eck, &ptr, sizeof(raw)) ) err("o2iECPublic=point");
  EVP_PKEY * pkey = EVP_PKEY_new(); 
  if( !EVP_PKEY_assign_EC_KEY(pkey, eck) ) err("PKEYassign");

  BIO *bio = BIO_new(BIO_s_mem());
  if( !PEM_write_bio_PUBKEY (bio, pkey) ) err("PEMwrite");
  char *pem = NULL; long len = BIO_get_mem_data (bio, &pem);
  fwrite (pem, 1, len, stdout); // for test; for real use as needed
  }  
return 0;
}

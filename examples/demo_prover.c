// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"
#include "simulated_loe.h"
#include "err.h"

#if CYC_GRP_BLS_G1 == 1

#else
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#endif


int
main (int argc, char **argv)
{
  uint64_t round;
  TLCSParty P;
  char *serialized_proof;
  FILE *fp;
  size_t len;
  if (argc != 2)
    {
      printf
	("Usage: %s [file]\n [file] will be used to write a serialized proof that will be given as input to the verifier and aggregator.\n",
	 argv[0]);
      exit (1);
    }
  fp = fopen (argv[1], "a");
  if (!fp)
    {
      printf ("error in opening the file\n");
      exit (1);
    }

  serialized_proof = (char *) malloc (5000000);



#if _DEBUG_ == 1
  clock_t begin, end;
  double time_spent;
#endif
  ASSERT (!pairing_init ());
#if CYC_GRP_BLS_G1 == 1
  ASSERT (!group_init ());
#else
//ASSERT(!group_init(NID_X9_62_prime256v1));
  printf
    ("For which curve do you want to generate the public keys?\nYou need to insert a valid NID number supported by openssl.\nSee in /usr/include/openssl/obj_mac.h\nExamples:\n\t* 714 for secp256k1\n\t* 415 for prime256v1\nInsert your choice:\n[No checks will be done so if the integer you insert is not valid the behavior will be unpredictable]\n");
  {
    int nid;
    scanf ("%d", &nid);
    ASSERT (!group_init (nid));
  }
#endif
  generate_loe_publickey ();





//round=1954572;
  printf
    ("Give me a round number in decimal format\n No check is done, so be careful to not add any unnecessary space or character.\n You can find the latest round here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/latest\n");
  scanf ("%" SCNu64 "", &round);
#if _DEBUG_ == 1

  printf ("Executing the protocol for round %" SCNu64 "\n", round);
#endif

#if _DEBUG_ == 1
  begin = clock ();
#endif
/* here, do your time-consuming job */

  ASSERT (!Prover (&P, round));
#if _DEBUG_ == 1
  end = clock ();
  time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
  printf
    ("time spent by the party in computing his public key and proof: %fs\n",
     time_spent);
#endif

  serialized_proof = SerializePartyOutput (&P.PK, &P.pi, &len);
  fwrite (serialized_proof, 1, len, fp);



  fclose (fp);
 Err ();
  return 0;
}

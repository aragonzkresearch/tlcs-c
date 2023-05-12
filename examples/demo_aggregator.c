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
#define NUM_PARTIES 2

#if CYC_GRP_BLS_G1 == 1

#else
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#endif


int
main (int argc, char **argv)
{
  int i;
  TLCSParty P[NUM_PARTIES];
  bool verified_proof[NUM_PARTIES];
  CycGrpG GPK;
  char *serialized_proof;
  FILE *fp, *fp2;
  size_t len;
  if (argc < 2)
    {
      printf
	("Usage: %s [file1] [file2] [list]\n[file1] will be used to read a serialized proof and [file2] will store the aggregated public key.[list] is a list of 0/1 elements representing the fact that the i-th proof (starting from i=0) is verified or not, e.g., \"1 1 0 1\" means that all proofs except the 3rd are verified. This sequence is given as output by demo_verifier.\n",
	 argv[0]);
      exit (1);
    }
  fp = fopen (argv[1], "r");
  fp2 = fopen (argv[2], "w");
  if (!fp || !fp2)
    {
      printf ("error in opening the file\n");
      exit (1);
    }



//time_t current=genesis+1955231*3;
  //   printf("%s", ctime(&current));
//return 0;

  serialized_proof = (char *) malloc (5000000);

  ASSERT (!pairing_init ());
#if CYC_GRP_BLS_G1 == 1
  ASSERT (!group_init ());
#else
//ASSERT(!group_init(NID_X9_62_prime256v1));
  printf
    ("For which curve have the public keys been generated?\nYou need to insert a valid NID number supported by openssl.\nSee in /usr/include/openssl/obj_mac.h\nExamples:\n\t* 714 for secp256k1\n\t* 415 for prime256v1\nInsert your choice:\n[No checks will be done so if the integer you insert is not valid the behavior will be unpredictable]\n");
  {
    int nid;
    scanf ("%d", &nid);
    ASSERT (!group_init (nid));
  }
#endif
  generate_loe_publickey ();

#if _DEBUG_ == 1

  printf ("Executing the aggregation protocol\n");
#endif

  fseek (fp, 0L, SEEK_END);
  len = ftell (fp);
  rewind (fp);
  fread (serialized_proof, 1, len, fp);
  fclose (fp);
  for (i = 0; i < NUM_PARTIES; i++)
    {

      DeserializePartyOutput (&P[i].PK, &P[i].pi, serialized_proof, &len);
      serialized_proof += len;
      if (atoi (argv[i + 3]) == 1)
	verified_proof[i] = true;
      else
	verified_proof[i] = false;
    }



#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpG_new (&GPK);
#endif

  AggregatePublicKeys (&GPK, P, NUM_PARTIES, verified_proof);
  fprintf (fp2, "%s", CycGrpG_toHexString (&GPK));
  fclose (fp2);
  err ();
  return 0;
}

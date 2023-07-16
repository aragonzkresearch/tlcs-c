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
#define MAX_NUM_PARTIES 10

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
  TLCSParty P[MAX_NUM_PARTIES];
  bool verified_proof[MAX_NUM_PARTIES];
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




  serialized_proof = (char *) malloc (5000000);

  pairing_init ();
#if CYC_GRP_BLS_G1 == 1
  group_init ();
#else
  {
    int nid;
    scanf ("%d", &nid);
    group_init (nid);
  }
#endif
  generate_loe_publickey ();


  fseek (fp, 0L, SEEK_END);
  len = ftell (fp);
  rewind (fp);
  fread (serialized_proof, 1, len, fp);
  fclose (fp);
  for (i = 0;; i++)
    {

      if (argv[i + 3] == NULL)
	{
	  break;
	}
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

  AggregatePublicKeys (&GPK, P, i, verified_proof);
  if (bjj_flag)
    {
      char *tmps;
      tmps = (char *) malloc (131);	// 131 is the length of a serialized bjj point
      Weierstrass2TwistedEdwards (tmps,
				  CycGrpG_toHexStringUncompressed (&GPK));
      fprintf (fp2, "%s", tmps);
    }
  else
    fprintf (fp2, "%s", CycGrpG_toHexString (&GPK));
  fclose (fp2);
  return 0;
}

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
#define MAX_NUM_PARTIES 10
int
main (int argc, char **argv)
{
  TLCSParty P[MAX_NUM_PARTIES];
  char *serialized_proof, *serialized_aggregated;
  uint64_t round;
  FILE *fp, *fp2;
  size_t len, len_aggregated;
  int i;
  size_t size, tmplen;
  CycGrpG GPK;
  CycGrpZp gsk;
  G1 Signature;
  bool verified_proof[MAX_NUM_PARTIES];
  if (argc <= 2)
    {
      printf
	("Usage: %s [file1] [file2] [list]\n [file1] will be used to read a list of serialized PKs and proofs, [file2] to read the aggregated PK to invert and [list] a list of 0/1 values representing whether the input of the i-th party has to be taken in account or not.\n",
	 argv[0]);
      exit (1);
    }
  fp = fopen (argv[1], "r");
  fp2 = fopen (argv[2], "r");
  if (!fp)
    {
      printf ("error in opening the file\n");
      exit (1);
    }

  serialized_proof = (char *) malloc (5000000);
  serialized_aggregated = (char *) malloc (5000);



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



  scanf ("%" SCNu64 "", &round);



  fseek (fp, 0L, SEEK_END);
  len = ftell (fp);
  rewind (fp);
  fread (serialized_proof, 1, len, fp);
  fclose (fp);
  i = size = tmplen = 0;

  fseek (fp2, 0L, SEEK_END);
  len_aggregated = ftell (fp2);
  rewind (fp2);
  fread (serialized_aggregated, 1, len_aggregated, fp2);
  fclose (fp2);
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpG_new (&GPK);
#endif
  if (bjj_flag)
    {
      char W[131];
      int ret;
      ret = TwistedEdwards2Weierstrass (W, serialized_aggregated);
      char E[131];
      Weierstrass2TwistedEdwards (E, W);
      if (ret == 1 || CycGrpG_fromHexString (&GPK, W) == -1)
	{
	  Log ("Error in deserializing the aggregate pk");
	  return -1;
	}
    }
  else
    CycGrpG_fromHexString (&GPK, serialized_aggregated);

// we set signature Signature to a real LOE's signature
//const  char *sigStr="9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0"; // this is the signature for round 1 of the unchained chain
//const char *sigStr="adda388d25a165bfb0efd8dba2f8ddab45ca7cbfdb64cbc7147aada71bf49a5239896c0608beed0ddbe24718d2d8b358"; // signature for round 1954572
  char sigStr[96 + 1];		// 96 is the length in hexadecimal of G1 points serialized in compressed form as published by LOE
  scanf ("%s", sigStr);
  set_loe_signature (&Signature, sigStr, strlen (sigStr));

  while (1)
    {

      if (DeserializePartyOutput
	  (&P[i].PK, &P[i].pi, serialized_proof + tmplen, &size) == -1)
	{
	  printf ("Error in deserializing the proof of party %d. Aborting\n",
		  i);
	  exit (1);
	}
      tmplen += size;
      if (argv[i + 3] == NULL)
	break;
      verified_proof[i] = (int) atoi (argv[i + 3]);

      i++;
      if (tmplen == len)
	break;
    }

  {
    CycGrpG Recovered_PK;
#if CYC_GRP_BLS_G1 == 1
#else
    CycGrpZp_new (&gsk);
    CycGrpG_new (&Recovered_PK);
#endif

    i = InvertAggregate (&gsk, P, i, &Signature, verified_proof);
    if (i != -1)
      {				// check that g^{gsk} =GPK 
	Log2 ("Error in inversion for party", i);
	return 1;
      }
    else
      {
	generate_public_key (&Recovered_PK, &gsk);
	if (!CycGrpG_isEqual (&Recovered_PK, &GPK))
	  {			// check that g^{gsk} =GPK 
	    Log ("Error in inversion");
	    return 1;
	  }
	else
	  {
	    printf ("sk:%s\n", CycGrpZp_toHexString (&gsk));

	  }
      }
  }
  return 0;
}

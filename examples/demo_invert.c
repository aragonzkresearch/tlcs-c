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
	("Usage: %s [file1] [file2] [list]\n [file1] will be used to read a list of serialized PK and proofs, [file2] to read the aggregated PK to invert and [list] a list of 0/1 values representing whether the input of the i-th party has to be taken in account or not.\n",
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



  ASSERT (!pairing_init ());
#if CYC_GRP_BLS_G1 == 1
  ASSERT (!group_init ());
#else
//ASSERT(!group_init(NID_X9_62_prime256v1));
  printf
    ("For which curve do you want to invert the public key?\nYou need to insert a valid NID number supported by openssl.\nSee in /usr/include/openssl/obj_mac.h\nExamples:\n\t* 714 for secp256k1\n\t* 415 for prime256v1\nInsert your choice:\n[No checks will be done so if the integer you insert is not valid the behavior will be unpredictable]\n");
  {
    int nid;
    scanf ("%d", &nid);
    ASSERT (!group_init (nid));
  }
#endif
  generate_loe_publickey ();



  printf
    ("Give me a round number in decimal format\n No check is done, so be careful to not add any unnecessary space or character.\n You can find the latest round here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/latest\n");
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
  CycGrpG_fromHexString (&GPK, serialized_aggregated);
  printf ("\nAggregate public key: %s %s\n", serialized_aggregated,
	  CycGrpG_toHexString (&GPK));

// we set signature Signature to a real LOE's signature
//const  char *sigStr="9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0"; // this is the signature for round 1 of the unchained chain
//const char *sigStr="adda388d25a165bfb0efd8dba2f8ddab45ca7cbfdb64cbc7147aada71bf49a5239896c0608beed0ddbe24718d2d8b358"; // signature for round 1954572
  printf ("\nGive me a signature in hexadecimal format for the round %" SCNu64
	  "\n You can find it here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/",
	  round);
  printf ("%" SCNu64 "/\n", round);
  char sigStr[96 + 1];		// 96 is the length in hexadecimal of G1 points serialized in compressed form as published by LOE
  scanf ("%s", sigStr);
  set_loe_signature (&Signature, sigStr, strlen (sigStr));

  while (1)
    {

      DeserializePartyOutput (&P[i].PK, &P[i].pi, serialized_proof + tmplen,
			      &size);
      tmplen += size;
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
	    Log2 ("Error in inversion for party", i);
	    return 1;
	  }
	else
	  {
	    printf ("Successfully inverted sk %s\n",
		    CycGrpZp_toHexString (&gsk));

	  }
      }
    Err ();
  }
  return 0;
}

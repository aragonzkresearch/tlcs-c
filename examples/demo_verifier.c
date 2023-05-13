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
  uint64_t round;
  TLCSParty P[MAX_NUM_PARTIES];
  char *serialized_proof;
  FILE *fp, *fp2;
  size_t len;
  int i, ret = 0;
  size_t size, tmplen;
  if (argc != 3)
    {
      printf
	("Usage: %s [file1] [file2]\n [file1] will be used to read a list of serialized proofs to verify and [file2] to write an arry of 0/1 representing whether the i-th proof is verified or not.\n",
	 argv[0]);
      exit (1);
    }
  fp = fopen (argv[1], "r");
  fp2 = fopen (argv[2], "w");
  if (!fp)
    {
      printf ("error in opening the file\n");
      exit (1);
    }

  serialized_proof = (char *) malloc (5000000);



  ASSERT (!pairing_init ());
#if CYC_GRP_BLS_G1 == 1
  ASSERT (!group_init ());
#else
//ASSERT(!group_init(NID_X9_62_prime256v1));
  printf
    ("For which curve do you want to verify the public keys?\nYou need to insert a valid NID number supported by openssl.\nSee in /usr/include/openssl/obj_mac.h\nExamples:\n\t* 714 for secp256k1\n\t* 415 for prime256v1\nInsert your choice:\n[No checks will be done so if the integer you insert is not valid the behavior will be unpredictable]\n");
  {
    int nid;
    scanf ("%d", &nid);
    ASSERT (!group_init (nid));
  }
#endif
  generate_loe_publickey ();





//round=1954572;
  printf
    ("Give me a round number in decimal format\n No check is done, so be careful to not add any unnecessary space or character.\n");
  scanf ("%" SCNu64 "", &round);
#if _DEBUG_ == 1

  printf ("Executing the verification for round %" SCNu64 "\n", round);
#endif


  fseek (fp, 0L, SEEK_END);
  len = ftell (fp);
  rewind (fp);
  fread (serialized_proof, 1, len, fp);
  fclose (fp);
  i = size = tmplen = 0;
  while (1)
    {

      DeserializePartyOutput (&P[i].PK, &P[i].pi, serialized_proof + tmplen,
			      &size);
      tmplen += size;
      ASSERT (!(ret = Verifier (&P[i].PK, &P[i].pi, round)));
      if (ret == 0)
	{
	  fprintf (fp2, " 1");
	}
      else
	{
	  fprintf (fp2, " 0");
	}
      if (tmplen == len)
	break;
      i++;
    }


  Err ();
  return 0;
}

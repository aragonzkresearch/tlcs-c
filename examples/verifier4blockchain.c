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
  {
    int nid;
    scanf ("%d", &nid);
    ASSERT (!group_init (nid));
  }
#endif
  generate_loe_publickey ();





//round=1954572;
  scanf ("%" SCNu64 "", &round);
#if _DEBUG_ == 1

#endif


  fseek (fp, 0L, SEEK_END);
  len = ftell (fp);
  rewind (fp);
  fread (serialized_proof, 1, len, fp);
  fclose (fp);
  i = size = tmplen = 0;
  while (1)
    {

      if (DeserializePartyOutput
	  (&P[i].PK, &P[i].pi, serialized_proof + tmplen, &size) == -1)
	{
	  fprintf (stderr, "Error in deserializing the proof of party %d. Aborting\n",
		  i);
fprintf (fp2, "0");
fflush(stdout);
	  exit (1);
	}
#if _SECRET_SHARING_ == 1
      ret = Verifier_SS (&P[i].PK, &P[i].pi, round);
#else
     ret = Verifier (&P[i].PK, &P[i].pi, round);
#endif
      tmplen += size;
      if (ret == 0)
	{
	  fprintf (fp2, "1");
	}
      else
	{
	  fprintf (fp2, "0");
	}
      if (tmplen == len)
	break;
      i++;
    }


  return 0;
}

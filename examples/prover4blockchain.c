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

#if _DEBUG_ == 1
  begin = clock ();
#endif
/* here, do your time-consuming job */

#if _SECRET_SHARING_ == 1
  ASSERT (!Prover_SS (&P, round));
#else
  ASSERT (!Prover (&P, round));
#endif
#if _DEBUG_ == 1
  end = clock ();
  time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
  Log3b (t);
#endif

  serialized_proof = SerializePartyOutput (&P.PK, &P.pi, &len);
  fwrite (serialized_proof, 1, len, fp);



  fclose (fp);
  Err ();
  return 0;
}

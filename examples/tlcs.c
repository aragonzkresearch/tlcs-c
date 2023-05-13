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
#if _DEBUG_ ==1
#include <time.h>
#endif
#define NUM_PARTIES 3

#if CYC_GRP_BLS_G1 == 1

#else
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#endif


static inline uint64_t
current_time_to_current_round (time_t current)
{
  return (current - loe_genesis_time) / loe_period;
}

static inline uint64_t
round_from_time (time_t current, unsigned int time_offset)
{
  return current_time_to_current_round (current) + 3 * time_offset;
}

int
main ()
{
  uint64_t round;
  int i, ret;
  TLCSParty P[NUM_PARTIES];
  TLCSParty P2[NUM_PARTIES];
  bool verified_proof[NUM_PARTIES];
  G1 Signature;
  CycGrpG GPK;
  CycGrpZp gsk;
  unsigned int time_offset;
  time_t current;
  char *serialized_proof;



//time_t current=genesis+1955231*3;
  //   printf("%s", ctime(&current));
//return 0;

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
  current = time (NULL);
  printf ("Now it is %s", ctime (&current));
//printf("Give me a round number in decimal format\n No check is done, so be careful to not add any unnecessary space or character.\n You can find the latest round here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/latest\n");
//scanf("%" SCNu64 "",&round);
  printf
    ("\nInsert a number X. The protocol will be executed to compute a public key that will be invertible 3*X seconds in the future since now.\nExample: if you insert 100 the protocol will output a public key that will be invertible in 5 minutes.\nNo check is done, so be careful to not add any unnecessary space or character.\n");
  scanf ("%u", &time_offset);
//You can find the latest round here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/latest\n");
  round = round_from_time (current, time_offset);
#if _DEBUG_ == 1

  printf ("Executing the protocol for round %" SCNu64 "\n", round);
#endif
  for (i = 0; i < NUM_PARTIES; i++)
    {

#if _DEBUG_ == 1
      begin = clock ();
#endif

      ASSERT (!Prover (&P[i], round));
#if _DEBUG_ == 1
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
      printf
	("time spent by party %d in computing his public key and proof: %fs\n",
	 i, time_spent);
#endif

      serialized_proof = SerializePartyOutput (&P[i].PK, &P[i].pi, NULL);
      DeserializePartyOutput (&P2[i].PK, &P2[i].pi, serialized_proof, NULL);
      free (serialized_proof);
#if _DEBUG_ == 1
      begin = clock ();
#endif
      ASSERT (!(ret = Verifier (&P[i].PK, &P[i].pi, round)));
#if _DEBUG_ == 1
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
      printf ("time spent by verifier on verifying proof of party %d: %fs\n",
	      i, time_spent);
#endif
      if (ret == 0)
	verified_proof[i] = true;
      else
	verified_proof[i] = false;

#if CYC_GRP_BLS_G1 == 1
#else
      CycGrpG_new (&GPK);
#endif




    }
  AggregatePublicKeys (&GPK, P, NUM_PARTIES, verified_proof);
  printf ("\nAggregate public key: %s\n", CycGrpG_toHexString (&GPK));

// uncomment as sanity check tp test a failed inversion (supposes inversion error for party i=3, so set NUM_PARTIES>=4)
//CycGrpG_add(&P[3].pi.C[0][0].PK,&P[3].pi.C[0][0].PK,&P[3].pi.C[0][0].PK);
#if PK_SIMULATED == 1		// in this case we are generating the signature by ourself because we simulated the public key and we know the corresponding secret key
  generate_loe_signature (&Signature, round);
#else // in this case we must set signature Signature to a real LOE's signature
//const  char *sigStr="9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0"; // this is the signature for round 1 of the unchained chain
//const char *sigStr="adda388d25a165bfb0efd8dba2f8ddab45ca7cbfdb64cbc7147aada71bf49a5239896c0608beed0ddbe24718d2d8b358"; // signature for round 1954572
  printf ("\nGive me a signature in hexadecimal format for the round %" SCNu64
	  "\n You can find it here: https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/",
	  round);
  printf ("%" SCNu64 "/\n", round);
  {
    time_t t = current + loe_period * time_offset;
    printf ("This website will be available only at time %s", ctime (&t));
  }
  char sigStr[96 + 1];		// 96 is the length in hexadecimal of G1 points serialized in compressed form as published by LOE
  scanf ("%s", sigStr);
  set_loe_signature (&Signature, sigStr, strlen (sigStr));
#endif
  {
    CycGrpG Recovered_PK;
//Invert(&inverted_sk,&P[0].PK,&Signature, &P[0].pi);
#if _DEBUG_ == 1
    printf ("\n");
    begin = clock ();
#endif
    i = InvertAggregate (&gsk, P, NUM_PARTIES, &Signature, verified_proof);
    if (i != -1)
      {
	printf ("Error in inversion for party %d\n", i);
      }
    else
      {
#if _DEBUG_ == 1
	end = clock ();
	time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
	printf ("time spent in inversion for %d parties: %fs\n", NUM_PARTIES,
		time_spent);
#endif
	generate_public_key (&Recovered_PK, &gsk);
	if (!CycGrpG_isEqual (&Recovered_PK, &GPK))
	  {			// check that g^{gsk} =GPK 
#if _DEBUG_ == 1
	    printf ("Error in inversion for party %d\n", i);
#endif
	    return 1;
	  }
#if _DEBUG_ == 1
	else
	  printf ("general secret key for round %lu successfully inverted\n",
		  round);
#endif
      }
  }
  Err ();
  return 0;
}

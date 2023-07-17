// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
// Improved by Craig Sailor, 2023, Aragon ZK Research
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

int main (int argc, char **argv) {
  TLCSParty P[MAX_NUM_PARTIES];
  char *serialized_proof, *serialized_aggregated;
  char *sigStr;
  uint64_t round;
  size_t len = 0;
  int i;
  int num_parties = 0;
  size_t size;
  CycGrpG GPK;
  CycGrpZp gsk;
  G1 Signature;
  bool verified_proof[MAX_NUM_PARTIES];

  serialized_proof = (char *) malloc (5000000);
  serialized_aggregated = (char *) malloc (5000);
  sigStr = (char *) malloc (5000);

  if (argc <= 3) {
      printf ("Usage: %s [round] [LOE signature] [aggregated PK] [file1] [file2] [list]\n [file1] will be used to read a list of serialized PKs and proofs, [file2] to read the aggregated PK to invert and [list] a list of 0/1 values representing whether the input of the i-th party has to be taken in account or not.\n", argv[0]);
      exit (1);
  }

  // Get Round
  int scanned = sscanf (argv[1], "%" SCNu64 "", &round);
  if (scanned != 1) {
    exit(1);
  }

  int sig_scanned = sscanf (argv[2], "%96s", sigStr);
  if (sig_scanned != 1) {
    exit(1);
  }

  int ser_scanned = sscanf (argv[3], "%s", serialized_aggregated);
  if (ser_scanned != 1) {
    exit(1);
  }

  int ch;
  while ((ch = getchar()) != EOF ) {
    serialized_proof[size] = ch;
    size++;
  }
  size--;

  pairing_init();

  #if CYC_GRP_BLS_G1 == 1
    group_init();
  #else
    group_init(0);
  #endif

  generate_loe_publickey();

  #if CYC_GRP_BLS_G1 == 1
  #else
    CycGrpG_new (&GPK);
  #endif

/////////////////
	if (bjj_flag) {
		char W[131];
		int ret;
		ret = TwistedEdwards2Weierstrass (W, serialized_aggregated);
		char E[131];
		Weierstrass2TwistedEdwards (E, W);

		if (ret == 1 || CycGrpG_fromHexString (&GPK, W) == -1) {
		  return -1;
		}
	} else {
	    CycGrpG_fromHexString (&GPK, serialized_aggregated);
	}
  ////////////////
  set_loe_signature (&Signature, sigStr, strlen(sigStr));

  while (1) {
    if (DeserializePartyOutput(&P[num_parties].PK, &P[num_parties].pi, serialized_proof, &len) >= 0 ) { 
	serialized_proof += len;
	verified_proof[num_parties] = true;
	num_parties++;
    } else {
	break;
    }
  }

  CycGrpG Recovered_PK;

  #if CYC_GRP_BLS_G1 == 1
  #else
    CycGrpZp_new (&gsk);
    CycGrpG_new (&Recovered_PK);
  #endif

  i = InvertAggregate(&gsk, P, num_parties, &Signature, verified_proof);

  // check that g^{gsk} =GPK 
  if (i != -1) {
    printf ("Error in inversion for party");
    return 1;
  } else {
    generate_public_key(&Recovered_PK, &gsk);

    // check that g^{gsk} =GPK 
    if (!CycGrpG_isEqual (&Recovered_PK, &GPK)) {
      printf ("Error in inversion");
      return 1;
    } else {
      printf ("sk:%s\n", CycGrpZp_toHexString (&gsk));
    }
  }

  return 0;
}

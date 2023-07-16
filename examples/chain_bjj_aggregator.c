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


int main (int argc, char **argv) {
  TLCSParty P[MAX_NUM_PARTIES];
  bool verified_proof[MAX_NUM_PARTIES];
  CycGrpG GPK;
  char *serialized_proof;
  size_t len, size = 0;
  int num_parties = 0;

  if (argc > 1) {
    if ((strcmp(argv[1],"-h")==0) || (strcmp(argv[1],"-help")==0)) {
      printf ("Usage: %s [proof list]\n\t[proof list] will be used to create the aggregated public key which will be returned via stdout.\n", argv[0]);
      exit (1);
    }
  }

  serialized_proof = (char *) malloc (5000000);

  pairing_init ();
  #if CYC_GRP_BLS_G1 == 1
    group_init ();
  #else
    group_init (0);
  #endif

  generate_loe_publickey ();

  int ch;
  while ((ch = getchar()) != EOF ) {
    serialized_proof[size] = ch;
    size++;
  }
  size--;

  while (1) {
    if (DeserializePartyOutput(&P[num_parties].PK, &P[num_parties].pi, serialized_proof, &len) >= 0 ) { 
	serialized_proof += len;
	verified_proof[num_parties] = true;
	num_parties++;
    } else {
	break;
    }
  }

  #if CYC_GRP_BLS_G1 == 1
  #else
    CycGrpG_new (&GPK);
  #endif

  AggregatePublicKeys (&GPK, P, num_parties, verified_proof);
	if (bjj_flag) {
		char *tmps;
		tmps = (char *) malloc (131);	// 131 is the length of a serialized bjj point
		Weierstrass2TwistedEdwards (tmps, CycGrpG_toHexStringUncompressed (&GPK));
  		fprintf (stdout, "%s", tmps);
	} else {
		fprintf (stdout, "%s", CycGrpG_toHexString(&GPK));
	}

	return 0;
}

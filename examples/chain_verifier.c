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
//#include "err.h"
#if CYC_GRP_BLS_G1 == 1

#else
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#endif

#define MAX_NUM_PARTIES 10
int main (int argc, char **argv) {
  uint64_t round;
  TLCSParty P[MAX_NUM_PARTIES];
  char *serialized_proof;
  int i = 0;
  int ret = 0;
  size_t size, tmplen, len = 0;

  // Check usage is correct
  if (argc != 2) {
    printf("Usage: %s [round] < [proof data]\n\t[round] is a LOE round and\n[proof data] is the proof to be verified.\n", argv[0]);
    exit (1);
  }

  // Get round number from argv
  int scanned = sscanf (argv[1], "%" SCNu64 "", &round);
  if (scanned != 1) {
    exit(1);
  }

  // Get input from stdin
  serialized_proof = (char *) malloc (5000000);
  int ch;
  while ( (ch = getchar()) != EOF ) {
    serialized_proof[size] = ch;
    size++;
  }
  size--;

  ASSERT (!pairing_init ());
  #if CYC_GRP_BLS_G1 == 1
    ASSERT (!group_init ());
  #else
    ASSERT (!group_init (714));
  #endif

  generate_loe_publickey();

  i = size = tmplen = 0;

  while (1) {
    if (DeserializePartyOutput(&P[i].PK, &P[i].pi, serialized_proof + tmplen, &size) == -1) {
      fprintf (stderr, "Error in deserializing the proof of party %d. Aborting\n", i);

      printf ("0");
      exit (1);
    }

    #if _SECRET_SHARING_ == 1
      ret = Verifier_SS (&P[i].PK, &P[i].pi, round);
    #else
      ret = Verifier (&P[i].PK, &P[i].pi, round);
    #endif

    tmplen += size;

    if (ret == 0) {
      printf ("1");
      exit (1);
    } else {
      printf ("0");
      exit (1);
    }

    if (tmplen == len)
      break;

    i++;
  }

  return 0;
}

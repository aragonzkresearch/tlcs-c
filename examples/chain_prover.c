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

int main (int argc, char **argv) {
  uint64_t round;
  TLCSParty P;
  char *serialized_proof;
  size_t len;

  if (argc != 2) {
    printf("Usage: %s [round]\n\t\"round\" is the LOE round.\n", argv[0]);
    exit (1);
  }

  int scanned = sscanf (argv[1], "%" SCNu64 "", &round);
  if (scanned != 1) {
    exit(1);
  }

  serialized_proof = (char *) malloc (5000000);

  ASSERT (!pairing_init ());

  #if CYC_GRP_BLS_G1 == 1
    ASSERT (!group_init ());
  #else
    ASSERT (!group_init (714));
  #endif

  generate_loe_publickey();

  #if _SECRET_SHARING_ == 1
    ASSERT (!Prover_SS (&P, round));
  #else
    ASSERT (!Prover (&P, round));
  #endif

  serialized_proof = SerializePartyOutput(&P.PK, &P.pi, &len);
  fwrite (serialized_proof, 1, len, stdout);

  return 0;
}

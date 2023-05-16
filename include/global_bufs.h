// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _GLOBALBUFS_H_
#define _GLOBALBUFS_H_ 1
#include <openssl/sha.h>
#if CYC_GRP_BLS_G1==1
#define SERIALIZATION_CYCGRPZP_RATIO 1
#else
#if CYC_GRP_RSA == 1
#define SERIALIZATION_CYCGRPZP_RATIO 33
#else
#define SERIALIZATION_CYCGRPZP_RATIO 3
#endif
#endif

#define MAX_LENGTH_SERIALIZATION (1<<15)
extern unsigned char buf_for_serializing[MAX_LENGTH_SERIALIZATION];
extern unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH *
				     SERIALIZATION_CYCGRPZP_RATIO];
#if PARALLELISM == 1
extern unsigned char
  buf_for_hashing_parallel_safe[NUM_REPETITIONS]
  [SHA256_DIGEST_LENGTH_CYCGRPZP_RATIO];
#endif


#endif

#include <openssl/sha.h>
#include "tlcs.h"
unsigned char buf_for_serializing[1024];
unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH *
			      SERIALIZATION_CYCGRPZP_RATIO];
#if PARALLELISM == 1
unsigned char
  buf_for_hashing_parallel_safe[NUM_REPETITIONS][SHA256_DIGEST_LENGTH *
						 SERIALIZATION_CYCGRPZP_RATIO];
#endif

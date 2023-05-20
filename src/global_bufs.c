#include <openssl/sha.h>
#include "tlcs.h"
unsigned char buf_for_serializing[MAX_LENGTH_SERIALIZATION];
unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH *
			      SERIALIZATION_CYCGRPZP_RATIO];

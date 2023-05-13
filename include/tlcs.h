// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _TLCS_H_
#define _TLCS_H_ 1
#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <mcl/bn_c384_256.h>
#include "cyclic_group.h"
#define NUM_REPETITIONS 80
#define NUM_COLUMNS 2
#define bool int
#define true 1
#define false 0
extern int g_err;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }
extern unsigned char buf_for_serializing[1024];
#if CYC_GRP_BLS_G1==1
#define SERIALIZATION_CYCGRPZP_RATIO 1
#else
#define SERIALIZATION_CYCGRPZP_RATIO 8
#endif
extern unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH *
				     SERIALIZATION_CYCGRPZP_RATIO];
// The constant 3 above has the following meaning.
// We assume that the serialization of the secret keys in CycGrpZp have length <=SHA256_DIGEST_LENGTH*3. Note that for simplicity now the serialization is not in binary so it consumes 64 bytes for keys of 32 bytes.

#if PARALLELISM ==1
extern unsigned char
  buf_for_hashing_parallel_safe[NUM_REPETITIONS][SHA256_DIGEST_LENGTH *
						 SERIALIZATION_CYCGRPZP_RATIO];
#endif


typedef struct
{
  G2 T;				// serialized element of G2 in hexadecimal
  CycGrpG PK;
  unsigned char y[SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO];

} CommitmentTuple;
typedef struct
{
//CycGrpZp sk;
  Zp t;				// serialized Zp in hexadecimal
} OpeningTuple;
typedef struct
{
  CommitmentTuple C[NUM_REPETITIONS][NUM_COLUMNS];
  OpeningTuple O[NUM_REPETITIONS];
} Proof;

typedef struct
{
  CycGrpZp sk;
  CycGrpG PK;
  Proof pi;
} TLCSParty;


void Err (void);
int Prover (TLCSParty * P, uint64_t round);
int Verifier (CycGrpG * PK, Proof * P, uint64_t round);
void AggregatePublicKeys (CycGrpG * GPK, TLCSParty P[], size_t num_parties,
			  bool verified_proof[]);
int Invert (CycGrpZp * sk, CycGrpG * PK, G1 * Signature, Proof * pi);


int InvertAggregate (CycGrpZp * gsk, TLCSParty P[], size_t num_parties,
		     G1 * Signature, bool verified_proof[]);
void ComputeChallenge (bool Challenge[], CycGrpG * PK,
		       CommitmentTuple C[][NUM_COLUMNS], uint64_t * round);
void XOR (unsigned char y[], CycGrpZp * sk, unsigned char sha256_digest[]);
void XOR_Verifier (CycGrpZp * sk, unsigned char HashZ[], unsigned char y[]);
int HashGTToBytes (unsigned char *buf, GT * e);
void HashRoundToG1 (G1 * g1, uint64_t * round);
char *SerializePartyOutput (const CycGrpG * PK, const Proof * pi,
			    size_t * size);
void DeserializePartyOutput (CycGrpG * PK, Proof * pi, const char *s,
			     size_t *);
char *SerializePKandCommitment (const CycGrpG * PK,
				const CommitmentTuple C[][NUM_COLUMNS]);
inline static void
set_loe_signature (G1 * Signature, const char *sigStr, size_t len)
{
  mclBn_setETHserialization (1);
  ASSERT (!
	  (mclBnG1_setStr
	   (Signature, sigStr, len, MCLBN_IO_SERIALIZE_HEX_STR)));
  mclBn_setETHserialization (0);
}
#endif

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
#include "global_bufs.h"
#include "cyclic_group.h"
#if _SECRET_SHARING_ == 1
//we implement and 2 out of 4 secret sharing
#define NUM_REPETITIONS 51
#define NUM_COLUMNS 3
#else
#define NUM_REPETITIONS 80
#define NUM_COLUMNS 2
#endif
#define bool int
#define true 1
#define false 0
extern int g_err;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }


typedef struct
{
  G2 T;				// serialized element of G2 in hexadecimal using Ethereum serialization
  CycGrpG PK;			// serialized element of CycGrpG in hexadecimal in compressed form (except for babyjubjub  that is uncompressed)
  unsigned char y[SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO];	// we serialize Zp in hexadecimal, so if a secret key sk has 32 bytes it will be converted in hexadecimale in 32*2 bytes but we include the ending null character and we pad with zeroes we end up with a string of 96 bytes. If a secret key has 64 bytes, it will be convered in hex in 64*2 bytes +  32 byte more for the null character and padding. In general we need SHA256_DIGEST_LENGTH*(2*Zp_length)+1, where Zp_length is the byte length of elements in Zp. For this reason  SERIALIZATION_CYCGRPZP_RATIO should be set to 3 for groups of order of bit length 256, to 5 for groups of order of bit length 512, etc.
//for numbers of 512 bits we will need 

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
  CycGrpG PK;			// serialized element of CycGrpG in hexadecimal in compressed form (except for babyjubjub  that is uncompressed)
  Proof pi;
} TLCSParty;



void Err (void);
int Prover (TLCSParty * P, uint64_t round);
int Prover_SS (TLCSParty * P, uint64_t round);
int Verifier (CycGrpG * PK, Proof * P, uint64_t round);
int Verifier_SS (CycGrpG * PK, Proof * P, uint64_t round);
void AggregatePublicKeys (CycGrpG * GPK, TLCSParty P[], size_t num_parties,
			  bool verified_proof[]);
int Invert (CycGrpZp * sk, CycGrpG * PK, G1 * Signature, Proof * pi);
int Invert_SS (CycGrpZp * sk, CycGrpG * PK, G1 * Signature, Proof * pi);


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
int DeserializePartyOutput (CycGrpG * PK, Proof * pi, const char *s,
			    size_t *);
char *SerializePKandCommitment (const CycGrpG * PK,
				const CommitmentTuple C[][NUM_COLUMNS]);
extern CycGrpZp LagrangeCoefficients[NUM_COLUMNS - 1][NUM_COLUMNS][2];
void ComputeLagrangeCoeff (void);
void AddWithLagrangeCoeff (CycGrpG * h, const CycGrpG * u, const CycGrpG * v,
			   int k1, int k2);
void InitTmpVar (void);
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

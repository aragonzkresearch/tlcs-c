// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "tlcs.h"
#include "pairing.h"
#include "simulated_loe.h"
#define get_index(a,n) ( (a[n/8] & (((unsigned char)1U) << (n%8))) %NUM_COLUMNS  )
static SHA256_CTX ctx;
void
ComputeChallenge (bool Challenge[], CycGrpG * PK,
		  CommitmentTuple C[][NUM_COLUMNS], uint64_t * round)
{
  int i;
  size_t len;
  char *s;
// We compute Challenge=SHA256(P->PK,P->pi,CommitmentTuple,round);
  SHA256_Init (&ctx);
  s = SerializePKandCommitment (PK, C);
  len = strlen (s);

  SHA256_Update (&ctx, (unsigned char *) s, len);
  SHA256_Update (&ctx, (unsigned char *) round, sizeof (uint64_t));
  SHA256_Final (buf_for_hashing, &ctx);
  for (i = 0; i < NUM_REPETITIONS; i++)
    Challenge[i] = get_index (buf_for_hashing, i);

}

inline void
XOR (unsigned char y[], CycGrpZp * sk, unsigned char sha256_digest[])	// sha256_digest is not 32 bytes but 32*SERIALIZATION_CYCGRPZP_RATIO
{
  int i;
  memset ((void *) buf_for_serializing, 0,
	  SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO);
  CycGrpZp_serialize (buf_for_serializing, MAX_LENGTH_SERIALIZATION, sk);
  for (i = 0; i < SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO; i++)
    y[i] = (unsigned char) (buf_for_serializing[i] ^ sha256_digest[i]);
}

inline int
HashGTToBytes (unsigned char *buf, GT * e)
{
  size_t length;
  length = GT_toHexString ((char *) buf_for_serializing, e);
//printf("GT: %d %s\n",length,buf_for_serializing);
  ASSERT (length);
  if (!length)
    return 1;
#if CYC_GRP_BLS_G1 == 1
  SHA256 (buf_for_serializing, length, buf);
#else
  {
    int k;
    for (k = 0; k < SERIALIZATION_CYCGRPZP_RATIO; k++)
      {				// we hash the element e so that it has SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO bytes. This is to be able to XOR with the maximum number of bytes that an element of CycGrpZp can contain. 
	buf_for_serializing[length] = k;
	SHA256 (buf_for_serializing, length, buf + k * SHA256_DIGEST_LENGTH);
      }
  }
#endif

  return 0;

}


inline void
HashRoundToG1 (G1 * g1, uint64_t * round)
{

  unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH];
  static SHA256_CTX ctx;
  uint64_t round_big_endian = __builtin_bswap64 (*round);

  SHA256_Init (&ctx);
  SHA256_Update (&ctx, (unsigned char *) &round_big_endian, 8);
  SHA256_Final (buf_for_hashing, &ctx);
  mclBnG1_hashAndMapTo (g1, (void *) buf_for_hashing, 32);
}

static inline void
ComputeShares (CycGrpZp shares[], CycGrpZp * s)
{				// s is the secret
// p(x)=Ax+s
// we evaluate it at points 1,..,NUM_COLUMNS
  char iStr[8];
  CycGrpZp A;
  CycGrpZp tmp, tmp2;
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpZp_new (&A);
  CycGrpZp_new (&tmp);
  CycGrpZp_new (&tmp2);
#endif
  CycGrpZp_setRand (&A);
  int i;
  for (i = 1; i <= NUM_COLUMNS; i++)
    {
#if CYC_GRP_BLS_G1 == 1
#else
      CycGrpZp_new (&shares[i - 1]);
#endif
      CycGrpZp_deserialize (&tmp2, (unsigned char *) iStr, 8);
      CycGrpZp_mul (&tmp, &A, &tmp2);
      CycGrpZp_add (&shares[i - 1], &tmp, s);

    }
/*
{
CycGrpG PK1,PK2,PK,S;
CycGrpG_new(&PK1);
CycGrpG_new(&PK2);
CycGrpG_new(&PK);
CycGrpG_new(&S);
CycGrpG_mul(&PK1,CycGrpGenerator,&shares[1]);
CycGrpG_mul(&PK2,CycGrpGenerator,&shares[3]);
CycGrpG_mul(&S,CycGrpGenerator,s);
ComputeLagrangeCoeff();
AddWithLagrangeCoeff(&PK,&PK1,&PK2,2,4);
//printf("S:%s PK:%s\n",CycGrpG_toHexString(&S),CycGrpG_toHexString(&PK));
}
*/
}

int
Prover_SS (TLCSParty * P, uint64_t round)
{
  int i;
  CycGrpZp sk[NUM_REPETITIONS][NUM_COLUMNS];
  Zp t[NUM_REPETITIONS][NUM_COLUMNS];
  GT Z[NUM_REPETITIONS][NUM_COLUMNS];
  G1 HashedRound;
  GT e;
  bool Challenge[NUM_REPETITIONS];

  generate_secret_key (&P->sk);
  generate_public_key (&P->PK, &P->sk);
  int j;
  for (i = 0; i < NUM_REPETITIONS; i++)
    {
#if CYC_GRP_BLS_G1 == 1
#else
      for (j = 0; j < NUM_COLUMNS; j++)
	CycGrpZp_new (&sk[i][j]);
#endif
      ComputeShares (sk[i], &P->sk);
      for (j = 0; j < NUM_COLUMNS; j++)
	Zp_setRand (&t[i][j]);
#if CYC_GRP_BLS_G1 == 1

      for (j = 0; j < NUM_COLUMNS; j++)
	CycGrpG_mul (&P->pi.C[i][j].PK, &CycGrpGenerator, &sk[i][j]);
#else
      for (j = 0; j < NUM_COLUMNS; j++)
	{
	  CycGrpG_new (&P->pi.C[i][j].PK);
	  CycGrpG_mul (&P->pi.C[i][j].PK, CycGrpGenerator, &sk[i][j]);
	}
#endif

      for (j = 0; j < NUM_COLUMNS; j++)
	G2_mul (&P->pi.C[i][j].T, &G2Generator, &t[i][j]);
    }
  HashRoundToG1 (&HashedRound, &round);	// HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))
  pairing (&e, &HashedRound, &PK_LOE);	// compute e=e(HashedRound,PK_LOE)

  for (i = 0; i < NUM_REPETITIONS; i++)
    {
      for (j = 0; j < NUM_COLUMNS; j++)
	GT_pow (&Z[i][j], &e, &t[i][j]);

      for (j = 0; j < NUM_COLUMNS; j++)
	{
	  HashGTToBytes (buf_for_hashing, &Z[i][j]);
	  XOR (P->pi.C[i][j].y, &sk[i][j], buf_for_hashing);
	}
    }
  ComputeChallenge (Challenge, &P->PK, P->pi.C, &round);
  for (i = 0; i < NUM_REPETITIONS; i++)
    {

      Zp_copy (&P->pi.O[i].t, &t[i][Challenge[i]]);
    }
  return 0;
}

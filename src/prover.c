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

#define get_bit(a,n) ( (a[n/8] & (((unsigned char)1U) << (n%8))) !=0  )
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
    Challenge[i] = get_bit (buf_for_hashing, i);

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
  //int length = GT_serialize (buf_for_serializing, MAX_LENGTH_SERIALIZATION, e);       // with BLS12-381 pairing length should 576 bytes
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




int
Prover (TLCSParty * P, uint64_t round)
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
  for (i = 0; i < NUM_REPETITIONS; i++)
    {
#if CYC_GRP_BLS_G1 == 1
#else
      CycGrpZp_new (&sk[i][0]);
      CycGrpZp_new (&sk[i][1]);
#endif
      CycGrpZp_setRand (&sk[i][0]);	// choose sk[i][0] randomly from Zq


      Zp_setRand (&t[i][0]);	// choose random t[i][0] from Zp
      Zp_setRand (&t[i][1]);
      CycGrpZp_sub (&sk[i][1], &P->sk, &sk[i][0]);	// sk[i][1]=sk-sk[i][0] so that sk=sk[i][0]+sk[i][1]
#if CYC_GRP_BLS_G1 == 1


      CycGrpG_mul (&P->pi.C[i][0].PK, &CycGrpGenerator, &sk[i][0]);	// PK[i][0]=g^{sk[i][0]}
      CycGrpG_mul (&P->pi.C[i][1].PK, &CycGrpGenerator, &sk[i][1]);
#else
      CycGrpG_new (&P->pi.C[i][0].PK);
      CycGrpG_new (&P->pi.C[i][1].PK);
      CycGrpG_mul (&P->pi.C[i][0].PK, CycGrpGenerator, &sk[i][0]);	// PK[i][0]=g^{sk[i][0]}
      CycGrpG_mul (&P->pi.C[i][1].PK, CycGrpGenerator, &sk[i][1]);
#endif

      G2_mul (&P->pi.C[i][0].T, &G2Generator, &t[i][0]);	// T[i][0]=g2^{t[i][0]} 
      G2_mul (&P->pi.C[i][1].T, &G2Generator, &t[i][1]);
    }
  HashRoundToG1 (&HashedRound, &round);	// HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))
  pairing (&e, &HashedRound, &PK_LOE);	// compute e=e(HashedRound,PK_LOE)

  for (i = 0; i < NUM_REPETITIONS; i++)
    {
      /* powers the previously precomputed element e to t[i][0], t[i][1] 
         to compute the resp. elements Z[i][0], Z[i][1]
         for all i=0,..., NUM_REPETITIONS-1  
       */
      GT_pow (&Z[i][0], &e, &t[i][0]);
      GT_pow (&Z[i][1], &e, &t[i][1]);
// now we hash  the Z[i][0], Z[i][1] and XOR them with the sk[i][0] ,sk[i][1] to compute the y[i][0],y[i][1]

      HashGTToBytes (buf_for_hashing, &Z[i][0]);	// buf_for_hashing holds SHA256(Z[i][0])
//P->pi.C[i][0].y=(unsigned char *)malloc(SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO);
//P->pi.C[i][1].y=(unsigned char *)malloc(SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO);
      XOR (P->pi.C[i][0].y, &sk[i][0], buf_for_hashing);	// y[i]= sk[i][0] XOR SHA256(Z[i][0])
      HashGTToBytes (buf_for_hashing, &Z[i][1]);
      XOR (P->pi.C[i][1].y, &sk[i][1], buf_for_hashing);
    }
  ComputeChallenge (Challenge, &P->PK, P->pi.C, &round);
  for (i = 0; i < NUM_REPETITIONS; i++)
    {

      Zp_copy (&P->pi.O[i].t, &t[i][Challenge[i]]);
    }
  return 0;
}

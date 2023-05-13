// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "tlcs.h"
#include "pairing.h"
#include "simulated_loe.h"
#if PARALLELISM == 1
#include <omp.h>
#endif
inline void
XOR_Verifier (CycGrpZp * sk, unsigned char HashZ[], unsigned char y[])
{
  int i;
//int length;
#if PARALLELISM == 1
  unsigned char buf_parallel_safe[MAX_LENGTH_SERIALIZATION];
#endif
  for (i = 0; i < SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO; i++)
#if PARALLELISM == 1

    buf_parallel_safe[i] = (unsigned char) (HashZ[i] ^ y[i]);
// length=CycGrpZp_deserialize(sk, buf_parallel_safe,sizeof(buf_parallel_safe)); 
  CycGrpZp_deserialize (sk, buf_parallel_safe, MAX_LENGTH_SERIALIZATION);
#else
    buf_for_serializing[i] = (unsigned char) (HashZ[i] ^ y[i]);
// length=CycGrpZp_deserialize(sk, buf_for_serializing,sizeof(buf_for_serializing)); 
  CycGrpZp_deserialize (sk, buf_for_serializing, MAX_LENGTH_SERIALIZATION);
#endif
//ASSERT(length);
}

int
Verifier (CycGrpG * PK, Proof * pi, uint64_t round)
{
  int i;
//CycGrpZp sk[NUM_REPETITIONS][NUM_COLUMNS];
//Zp t[NUM_REPETITIONS];
  GT Z[NUM_REPETITIONS];
//CycGrpG TMPPK[NUM_REPETITIONS];
  G2 T[NUM_REPETITIONS];
  G1 HashedRound;
  GT e;
  bool Challenge[NUM_REPETITIONS];
#if PARALLELISM == 1
  CycGrpG GTmp[NUM_REPETITIONS];
  CycGrpZp s[NUM_REPETITIONS];
  CycGrpG PK_parallel_safe[NUM_REPETITIONS];
#else
  CycGrpG GTmp;
  CycGrpZp s;
#endif
  int ret = 0;
  HashRoundToG1 (&HashedRound, &round);	// HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))
  pairing (&e, &HashedRound, &PK_LOE);	// compute e=e(HashedRound,PK_LOE)

  ComputeChallenge (Challenge, PK, pi->C, &round);
#if PARALLELISM == 1
  for (i = 0; i < NUM_REPETITIONS; i++)
    {
#if CYC_GRP_BLS_G1 ==1
#else
      CycGrpG_new (&PK_parallel_safe[i]);
#endif
      CycGrpG_copy (&PK_parallel_safe[i], PK);
    }
//#pragma omp parallel 
  {
#pragma omp for
#endif
    for (i = 0; i < NUM_REPETITIONS; i++)
      {
	if (ret == 1)
	  continue;

#if PARALLELISM == 1

#if CYC_GRP_BLS_G1 ==1
#else
	CycGrpG_new (&GTmp[i]);
#endif


	CycGrpG_add (&GTmp[i], &pi->C[i][0].PK, &pi->C[i][1].PK);
	if (!CycGrpG_isEqual (&GTmp[i], &PK_parallel_safe[i]))
	  {
#else

#if CYC_GRP_BLS_G1 ==1
#else
	CycGrpG_new (&GTmp);
#endif

	CycGrpG_add (&GTmp, &pi->C[i][0].PK, &pi->C[i][1].PK);

	if (!CycGrpG_isEqual (&GTmp, PK))
	  {
#endif
	    printf ("Verifier: error1 in repetition %d\n", i);
	    ret = 1;
	    continue;
	  }
	/* powers the previously precomputed element e to t[i] 
	   to compute the resp. elements Z[i]
	   for all i=0,..., NUM_REPETITIONS-1  
	 */
	GT_pow (&Z[i], &e, &pi->O[i].t);
// now we hash  the Z[i] and XOR them with the y[i][Challenge_i] to verify equality with the element sk[i][Challenge_i]
#if PARALLELISM == 1

#if CYC_GRP_BLS_G1 ==1
#else
	CycGrpZp_new (&s[i]);
#endif

	HashGTToBytes (buf_for_hashing_parallel_safe[i], &Z[i]);	// buf_for_hashing holds SHA256(Z[i])
	XOR_Verifier (&s[i], pi->C[i][Challenge[i]].y, buf_for_hashing_parallel_safe[i]);	// s= y[i][Challenge_i] XOR SHA256(Z[i])
#if CYC_GRP_BLS_G1 ==1
	CycGrpG_mul (&GTmp[i], &CycGrpGenerator, &s[i]);
#else
	CycGrpG_mul (&GTmp[i], CycGrpGenerator, &s[i]);
#endif
#else


#if CYC_GRP_BLS_G1 ==1
#else
	CycGrpZp_new (&s);
#endif

	HashGTToBytes (buf_for_hashing, &Z[i]);	// buf_for_hashing holds SHA256(Z[i])
	XOR_Verifier (&s, pi->C[i][Challenge[i]].y, buf_for_hashing);	// s= y[i][Challenge_i] XOR SHA256(Z[i])


#if CYC_GRP_BLS_G1 ==1
	CycGrpG_mul (&GTmp, &CycGrpGenerator, &s);
#else
	CycGrpG_mul (&GTmp, CycGrpGenerator, &s);
#endif

#endif


#if PARALLELISM == 1
	if (!CycGrpG_isEqual
	    (&GTmp[i], &pi->C[i][(unsigned int) Challenge[i]].PK))
	  {			// check that g^s =PK[i][Challenge_i] 
#else
	if (!CycGrpG_isEqual
	    (&GTmp, &pi->C[i][(unsigned int) Challenge[i]].PK))
	  {			// check that g^s =PK[i][Challenge_i] 
#endif
	    printf ("Verifier: error2 in repetition %d\n", i);
	    ret = 1;
	    continue;
	  }
	G2_mul (&T[i], &G2Generator, &pi->O[i].t);	// T[i]=g2^{t[i}]
	if (!G2_isEqual (&T[i], &pi->C[i][(unsigned int) Challenge[i]].T))
	  {			// check that T[i] equals the value T[i][Challenge[i]] from the proof
	    printf ("Verifier: error3 in repetition %d\n", i);
	    ret = 1;
	    continue;
	  }
      }
#if PARALLELISM == 1
  }
#endif
  if (ret == 0)
    return 0;
  else
    return 1;
}

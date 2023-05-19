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
#include "err.h"
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

static CycGrpZp Tmp1, Tmp2, Tmp3;
static CycGrpG GTmp1, GTmp2;
inline void
InitTmpVar (void)
{
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpZp_new (&Tmp1);
  CycGrpZp_new (&Tmp2);
  CycGrpZp_new (&Tmp3);
  CycGrpG_new (&GTmp1);
  CycGrpG_new (&GTmp2);
#endif

}

CycGrpZp LagrangeCoefficients[NUM_COLUMNS - 1][NUM_COLUMNS][2];	// The lagrange coefficient Lambda_{S,b} of the ordered pair S=(k1,k2) for b in {0,1}, k1 in {1,...,NUM_COLUMNS -1}, k2 in {1,...,NUM_COLUMNS}, where Lambda_{S,0} denotes Lambda_{S,k1} and Lambda_{S,1} denotes Lambda_{S,k2}, will be stored in LagrangeCoefficients[k1-1][k2-1][b].
// Note: only the half of this array will be used but we prefer simplicity
void
ComputeLagrangeCoeff (void)
{
  int k1, k2;
  char k1Str[32], k2Str[32];
  for (k1 = 1; k1 < NUM_COLUMNS; k1++)
    for (k2 = k1 + 1; k2 <= NUM_COLUMNS; k2++)
      {
#if CYC_GRP_BLS_G1 == 1
#else
	CycGrpZp_new (&LagrangeCoefficients[k1 - 1][k2 - 1][0]);
	CycGrpZp_new (&LagrangeCoefficients[k1 - 1][k2 - 1][1]);
#endif
// Lambda_{(k1,k2),0}=k2/(k2-k1) mod p
// Lambda_{(k1,k2),1}=k1/(k1-k2) mod p
	snprintf (k1Str, 8, "%x", k1);
	snprintf (k2Str, 8, "%x", k2);
	CycGrpZp_deserialize (&Tmp1, (unsigned char *) k1Str, 8);
	CycGrpZp_deserialize (&Tmp2, (unsigned char *) k2Str, 8);
	CycGrpZp_sub (&Tmp3, &Tmp2, &Tmp1);
	CycGrpZp_inverse (&Tmp3, &Tmp3);
	CycGrpZp_mul (&LagrangeCoefficients[k1 - 1][k2 - 1][0], &Tmp2, &Tmp3);
	CycGrpZp_sub (&Tmp3, &Tmp1, &Tmp2);
	CycGrpZp_inverse (&Tmp3, &Tmp3);
	CycGrpZp_mul (&LagrangeCoefficients[k1 - 1][k2 - 1][1], &Tmp1, &Tmp3);
      }

}

inline void
AddWithLagrangeCoeff (CycGrpG * h, const CycGrpG * u, const CycGrpG * v,
		      int k1, int k2)
{				// h=u^Lambda_0*v^Lambda_1 where Lambda_0=Lambda_{(k1,k2),k1} and similarly Lambda_1
//printf("Lambda_{(%d,%d),0}=%s\n",k1,k2,CycGrpZp_toHexString(&LagrangeCoefficients[k1-1][k2-1][0]));
//printf("Lambda_{(%d,%d),1}=%s\n",k1,k2,CycGrpZp_toHexString(&LagrangeCoefficients[k1-1][k2-1][1]));
  CycGrpG_mul (&GTmp1, u, &LagrangeCoefficients[k1 - 1][k2 - 1][0]);
  CycGrpG_mul (&GTmp2, v, &LagrangeCoefficients[k1 - 1][k2 - 1][1]);
  CycGrpG_add (h, &GTmp1, &GTmp2);
//printf("h:%s\n",CycGrpG_toHexString(h));
}

int
Verifier_SS (CycGrpG * PK, Proof * pi, uint64_t round)
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

  InitTmpVar ();
  ComputeLagrangeCoeff ();
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
	  goto endfor;
#if CYC_GRP_BLS_G1 ==1
#else
#if PARALLELISM == 1
	CycGrpG_new (&GTmp[i]);
#else
	CycGrpG_new (&GTmp);
#endif
#endif
	int k1, k2;
	for (k1 = 1; k1 < NUM_COLUMNS; k1++)
	  for (k2 = k1 + 1; k2 <= NUM_COLUMNS; k2++)
	    {
#if PARALLELISM == 1
	      AddWithLagrangeCoeff (&GTmp[i], &pi->C[i][k1 - 1].PK,
				    &pi->C[i][k2 - 1].PK, k1, k2);
#else
	      AddWithLagrangeCoeff (&GTmp, &pi->C[i][k1 - 1].PK,
				    &pi->C[i][k2 - 1].PK, k1, k2);
#endif
#if PARALLELISM == 1
	      if (!CycGrpG_isEqual (&GTmp[i], PK))
#else
	      if (!CycGrpG_isEqual (&GTmp, PK))
#endif
		{
		  Log2 ("Verifier: error1 in repetition", i);
		  ret = 1;
		  goto endfor;
		}
	    }
	GT_pow (&Z[i], &e, &pi->O[i].t);
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
	  {
#else
	if (!CycGrpG_isEqual
	    (&GTmp, &pi->C[i][(unsigned int) Challenge[i]].PK))
	  {
#endif
	    Log2 ("Verifier: error2 in repetition\n", i);
	    ret = 1;
	    goto endfor;
	  }
	G2_mul (&T[i], &G2Generator, &pi->O[i].t);
	if (!G2_isEqual (&T[i], &pi->C[i][(unsigned int) Challenge[i]].T))
	  {
	    Log2 ("Verifier: error3 in repetition", i);
	    ret = 1;
	    goto endfor;
	  }

      endfor:;
      }
#if PARALLELISM == 1
  }
#endif
  if (ret == 0)
    return 0;
  else
    return 1;
}

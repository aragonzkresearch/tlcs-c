// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include "tlcs.h"
#include "pairing.h"
#include "err.h"
#include "simulated_loe.h"

inline void
XOR_Verifier (CycGrpZp * sk, unsigned char HashZ[], unsigned char y[])
{
  int i;
  for (i = 0; i < SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO; i++)
    buf_for_serializing[i] = (unsigned char) (HashZ[i] ^ y[i]);
  CycGrpZp_deserialize (sk, buf_for_serializing, MAX_LENGTH_SERIALIZATION);
}

static CycGrpZp Tmp1, Tmp2, Tmp3;
static CycGrpG GTmp1, GTmp2;
void
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
{
  // h=u^Lambda_0*v^Lambda_1 where Lambda_0=Lambda_{(k1,k2),k1} and similarly Lambda_1
#if CYCGRP_BLS_G1 == 1
  CycGrpG_mul (&GTmp1, u, &LagrangeCoefficients[k1 - 1][k2 - 1][0]);
  CycGrpG_mul (&GTmp2, v, &LagrangeCoefficients[k1 - 1][k2 - 1][1]);
  CycGrpG_add (h, &GTmp1, &GTmp2);
#else
  {
// Recall: in case NUM_COLUMNS == 3 then:
//  Lambda_{(k1,k2),0}=k2/(k2-k1) mod p
// Lambda_{(k1,k2),1}=k1/(k1-k2) mod p
// so Lambda_{(1,2),0)=2
// so Lambda_{(1,2),1)=-1
// so Lambda_{(2,3),0)=3
// so Lambda_{(2,3),1)=-2
// so we treat these special cases separately for efficiency
#if NUM_COLUMNS == 3
    if (k1 == 1 && k2 == 2)
      {
	EC_POINT *tmp, *tmp2;
	tmp = EC_POINT_new (ec_group);
	tmp2 = EC_POINT_new (ec_group);
	EC_POINT_dbl (ec_group, tmp, u->P, bn_ctx);
	EC_POINT_copy (tmp2, v->P);
	EC_POINT_invert (ec_group, tmp2, bn_ctx);
	EC_POINT_add (ec_group, h->P, tmp, tmp2, bn_ctx);
	return;
      }
    else if (k1 == 2 && k2 == 3)
      {
	EC_POINT *tmp, *tmp2;
	tmp = EC_POINT_new (ec_group);
	tmp2 = EC_POINT_new (ec_group);
	EC_POINT_dbl (ec_group, tmp, u->P, bn_ctx);
	EC_POINT_add (ec_group, tmp, tmp, u->P, bn_ctx);
	EC_POINT_copy (tmp2, v->P);
	EC_POINT_invert (ec_group, tmp2, bn_ctx);
	EC_POINT_dbl (ec_group, tmp2, tmp2, bn_ctx);
	EC_POINT_add (ec_group, h->P, tmp, tmp2, bn_ctx);
	return;
      }
#endif
    BIGNUM *m[2];
    EC_POINT *p[2];
    m[0] = LagrangeCoefficients[k1 - 1][k2 - 1][0].B;
    m[1] = LagrangeCoefficients[k1 - 1][k2 - 1][1].B;
    p[0] = u->P;
    p[1] = v->P;
    EC_POINTs_mul (ec_group, h->P, NULL, 2, (const EC_POINT **) p,
		   (const BIGNUM **) m, bn_ctx);
  }
#endif
}

int
Verifier_SS (CycGrpG * PK, Proof * pi, uint64_t round)
{
  int i;
  GT Z[NUM_REPETITIONS];
  G2 T[NUM_REPETITIONS];
  G1 HashedRound;
  GT e;
  bool Challenge[NUM_REPETITIONS];
  CycGrpG GTmp;
  CycGrpZp s;
  int ret = 0;
  HashRoundToG1 (&HashedRound, &round);	// HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))
  pairing (&e, &HashedRound, &PK_LOE);	// compute e=e(HashedRound,PK_LOE)

  ComputeChallenge (Challenge, PK, pi->C, &round);
  for (i = 0; i < NUM_REPETITIONS; i++)
    {
      if (ret == 1)
	goto endfor;
#if CYC_GRP_BLS_G1 ==1
#else
      CycGrpG_new (&GTmp);
#endif
      int k1, k2;
      for (k1 = 1; k1 < NUM_COLUMNS; k1++)
	for (k2 = k1 + 1; k2 <= NUM_COLUMNS; k2++)
	  {
	    AddWithLagrangeCoeff (&GTmp, &pi->C[i][k1 - 1].PK,
				  &pi->C[i][k2 - 1].PK, k1, k2);
	    if (!CycGrpG_isEqual (&GTmp, PK))
	      {
		Log2 ("Verifier: error1 in repetition", i);
		ret = 1;
		goto endfor;
	      }
	  }
      GT_pow (&Z[i], &e, &pi->O[i].t);

/*
 {
int z; 
double time_spent,begin,end;
     begin = clock ();
for (z=0;z<3000;z++)
	GT_pow (&Z[i], &e, &pi->O[i].t);
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC/3000;
printf("average time for exp. in GT: %f\n",time_spent);
}
*/

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

/* 
{
int z; 
double time_spent,begin,end;
     begin = clock ();
for (z=0;z<3000;z++)
	CycGrpG_mul (&GTmp, CycGrpGenerator, &s);
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC/3000;
printf("average time for exp. in G: %f\n",time_spent);
}
*/


      if (!CycGrpG_isEqual (&GTmp, &pi->C[i][(unsigned int) Challenge[i]].PK))
	{
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
  if (ret == 0)
    return 0;
  else
    return 1;
}

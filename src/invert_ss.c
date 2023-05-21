// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "tlcs.h"
#include "err.h"
#include "pairing.h"
#include "simulated_loe.h"
static CycGrpZp ZTmp1, ZTmp2;
inline void
InitTmpVar2 (void)
{
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpZp_new (&ZTmp1);
  CycGrpZp_new (&ZTmp2);
#endif

}

void
AddScalarsWithLagrangeCoeff (CycGrpZp * h, const CycGrpZp * u,
			     const CycGrpZp * v, int k1, int k2)
{				// h=u*Lambda_0+v*Lambda_1 where Lambda_0=Lambda_{(k1,k2),k1} and similarly Lambda_1
//printf("Lambda_{(%d,%d),0}=%s\n",k1,k2,CycGrpZp_toHexString(&LagrangeCoefficients[k1-1][k2-1][0]));
//printf("Lambda_{(%d,%d),1}=%s\n",k1,k2,CycGrpZp_toHexString(&LagrangeCoefficients[k1-1][k2-1][1]));
  CycGrpZp_mul (&ZTmp1, u, &LagrangeCoefficients[k1 - 1][k2 - 1][0]);
  CycGrpZp_mul (&ZTmp2, v, &LagrangeCoefficients[k1 - 1][k2 - 1][1]);
  CycGrpZp_add (h, &ZTmp1, &ZTmp2);
//printf("h:%s\n",CycGrpG_toHexString(h));
}

int
Invert_SS (CycGrpZp * sk, CycGrpG * PK, G1 * Signature, Proof * pi)
{
  int i;
  GT Z;
  CycGrpZp sktmp;
  CycGrpG GTmp;
  CycGrpZp s[2];
  int k1, k2;
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpG_new (&GTmp);
  CycGrpZp_new (&s[0]);
  CycGrpZp_new (&s[1]);
  CycGrpZp_new (&sktmp);
#endif
  InitTmpVar ();
  InitTmpVar2 ();
  ComputeLagrangeCoeff ();
  for (i = 0; i < NUM_REPETITIONS; i++)
    {
      for (k1 = 1; k1 < NUM_COLUMNS; k1++)
	for (k2 = k1 + 1; k2 <= NUM_COLUMNS; k2++)
	  {
	    AddWithLagrangeCoeff (&GTmp, &pi->C[i][k1 - 1].PK,
				  &pi->C[i][k2 - 1].PK, k1, k2);
	    if (!CycGrpG_isEqual (&GTmp, PK))
	      {
#if _DEBUG_ == 1
		Log2 ("Invert_SS: error1 in repetition", i);
#endif
		//      return 1;
		continue;
	      }


	    pairing (&Z, Signature, &pi->C[i][k1-1].T);
	    HashGTToBytes (buf_for_hashing, &Z);
	    XOR_Verifier (&s[0], pi->C[i][k1-1].y, buf_for_hashing);
	    pairing (&Z, Signature, &pi->C[i][k2-1].T);
	    HashGTToBytes (buf_for_hashing, &Z);
	    XOR_Verifier (&s[1], pi->C[i][k2-1].y, buf_for_hashing);
	    AddScalarsWithLagrangeCoeff (&sktmp, &s[0], &s[1], k1, k2);
#if CYC_GRP_BLS_G1 == 1
	    CycGrpG_mul (&GTmp, &CycGrpGenerator, &sktmp);
#else
	    CycGrpG_mul (&GTmp, CycGrpGenerator, &sktmp);
#endif
	    if (!CycGrpG_isEqual (&GTmp, PK))
	      {			

#if _DEBUG_ == 1
		Log2 ("Invert_SS: error2 in repetition", i);
#endif
		//      return 1;
		continue;
	      }
	    else
	      {
		CycGrpZp_copy (sk, &sktmp);
#if _DEBUG_ == 1
#if _DEBUG_VERBOSE_ == 1
		Log2 ("party' sk found out in repetition", i);
#endif
#endif
		return 0;
	      }
	  }
    }
  return 1;
}

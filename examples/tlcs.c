// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"
#include "simulated_loe.h"
#if _DEBUG_ ==1
#include <time.h>
#endif
#define NUM_PARTIES 1





int main()
{
uint64_t round;
int i,ret;
TLCSParty P[NUM_PARTIES];
bool verified_proof[NUM_PARTIES];
G1 Signature;
CycGrpG GPK;
CycGrpZp gsk;
#if _DEBUG_ == 1
clock_t begin,end;
double time_spent;
#endif
ASSERT(!pairing_init());
ASSERT(!group_init());
generate_loe_publickey();

round=1;
for (i=0;i<NUM_PARTIES;i++){

#if _DEBUG_ == 1
begin = clock();
#endif
/* here, do your time-consuming job */

ASSERT(!Prover(&P[i],round));
#if _DEBUG_ == 1
end = clock();
 time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
printf("time spent by prover on a single party: %fs\n",time_spent);
#endif
generate_loe_signature(&Signature,round);
#if _DEBUG_ == 1
begin = clock();
#endif
ASSERT(!(ret=Verifier(&P[i].PK,&P[i].pi,round)));
#if _DEBUG_ == 1
end = clock();
 time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
printf("time spent by verifier on a single party: %fs\n",time_spent);
#endif
if (ret==0) verified_proof[i]=true;
else verified_proof[i]=false;

AggregatePublicKeys(&GPK,P,NUM_PARTIES,verified_proof);
}
// uncomment as sanity check tp test a failed inversion (supposes inversion error for party i=3, so set NUM_PARTIES>=4)
//CycGrpG_add(&P[3].pi.C[0][0].PK,&P[3].pi.C[0][0].PK,&P[3].pi.C[0][0].PK);
{
CycGrpG Recovered_PK;
//Invert(&inverted_sk,&P[0].PK,&Signature, &P[0].pi);
#if _DEBUG_ == 1
begin = clock();
#endif
i=InvertAggregate(&gsk,P,NUM_PARTIES,&Signature,verified_proof);
#if _DEBUG_ == 1
end = clock();
 time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
printf("time spent in inversion for %d parties: %fs\n",NUM_PARTIES,time_spent);
#endif
generate_public_key(&Recovered_PK,&gsk);
if (!CycGrpG_isEqual(&Recovered_PK,&GPK)) { // check that g^{gsk} =GPK 
#if _DEBUG_ == 1
printf("Error in inversion for party %d\n",i);
#endif 
return 1; 
}
#if _DEBUG_ == 1
else 
printf("general secret key successfully inverted\n");
#endif
}
err();
return 0;
}

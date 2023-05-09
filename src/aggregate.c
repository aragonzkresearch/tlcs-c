// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research

#include "tlcs.h"
#include "pairing.h"
#include "simulated_loe.h"

void AggregatePublicKeys(CycGrpG *GPK,TLCSParty P[],size_t num_parties, bool verified_proof[]){ // assume at least one verified_proof  and proofs are for the same round
unsigned int i,flag=0;
for (i=0;i<num_parties;i++) if (verified_proof[i]==true) { // add parties' pubkeys only if corresponding proofs are verified
if (!flag) {
CycGrpG_copy(GPK,&P[i].PK);
flag=1;
}
else {
CycGrpG_add(GPK,GPK,&P[i].PK);
}
}
// in the end GPK contains the pubkey of time t
}
int InvertAggregate(CycGrpZp *gsk,TLCSParty P[],size_t num_parties,G1 *Signature,bool verified_proof[]){ // return -1 on success and i for the number of party for which it failed
unsigned int i,flag=0;
CycGrpZp inverted_sk;
#if CYC_GRP_BLS_G1 == 1
#else
CycGrpZp_new(&inverted_sk);
#endif

for (i=0;i<num_parties;i++) if (verified_proof[i]==true)
{
 if (!Invert(&inverted_sk,&P[i].PK,Signature, &P[i].pi)) { 
if (!flag) {
CycGrpZp_copy(gsk,&inverted_sk);
flag=1;
}
else {
CycGrpZp_add(gsk,gsk,&inverted_sk);
}
} else return i;



}

return -1; 
}

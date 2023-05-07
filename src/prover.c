// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
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

#define get_bit(a,n) ( (a[n/8] & (((unsigned char)1U) << (n%8))) !=0  )
unsigned char buf_for_serializing[1024]; 
unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH];
#if PARALLELISM == 1 
unsigned char buf_for_hashing_parallel_safe[NUM_REPETITIONS][SHA256_DIGEST_LENGTH]; 
#endif 
static SHA256_CTX ctx;
inline  void ComputeChallenge(bool Challenge[],CycGrpG *PK,CommitmentTuple C[][NUM_COLUMNS],uint64_t *round){
int i;
// We compute Challenge=SHA256(P->PK,P->pi,CommitmentTuple,round);
SHA256_Init(&ctx);
SHA256_Update(&ctx, (unsigned char*)PK, sizeof(CycGrpG));
SHA256_Update(&ctx, (unsigned char *)C, sizeof(CommitmentTuple)*NUM_REPETITIONS*NUM_COLUMNS);
SHA256_Update(&ctx, (unsigned char *)round, sizeof(uint64_t));
SHA256_Final(buf_for_hashing, &ctx);
for (i=0;i<NUM_REPETITIONS;i++) Challenge[i]= get_bit(buf_for_hashing,i);

}

inline void XOR(unsigned char y[], CycGrpZp *sk, unsigned char sha256_digest[]){
int i;
#if PARALLELISM == 1
unsigned char buf_parallel_safe[1024];
int length=CycGrpZp_serialize(buf_parallel_safe,sizeof(buf_parallel_safe),sk); 
ASSERT(length);
for(i=0; i<SHA256_DIGEST_LENGTH;i++)
       y[i] = (unsigned char)(buf_parallel_safe[i] ^ sha256_digest[i]);
#else
int length=CycGrpZp_serialize(buf_for_serializing,sizeof(buf_for_serializing),sk); 
ASSERT(length);
for(i=0; i<SHA256_DIGEST_LENGTH;i++)
       y[i] = (unsigned char)(buf_for_serializing[i] ^ sha256_digest[i]);
#endif
}
inline int HashGTToBytes(unsigned char *buf,GT *e){

#if PARALLELISM == 1
unsigned char buf_parallel_safe[1024];
int length=GT_serialize(buf_parallel_safe,sizeof(buf_parallel_safe),e); // with BLS12-381 pairing length should 576 bytes
ASSERT(length);
if (!length) return 1;
SHA256(buf_parallel_safe,length,buf);
#else
int length=GT_serialize(buf_for_serializing,sizeof(buf_for_serializing),e); // with BLS12-381 pairing length should 576 bytes
ASSERT(length);
if (!length) return 1;
SHA256(buf_for_serializing,length,buf);
#endif
return 0;

}
static unsigned char tmp_bytes[8];
inline static void round_to_bytes(unsigned char *bytes,uint64_t *round){
memcpy(bytes,round,sizeof(uint64_t));
}

inline void HashRoundToG1(G1 *g1,uint64_t *round){
round_to_bytes(&tmp_bytes[0],round);
G1_hashAndMapTo(g1,&tmp_bytes[0],sizeof(uint64_t));
}




int Prover(TLCSParty *P,uint64_t round){
int i;
CycGrpZp sk[NUM_REPETITIONS][NUM_COLUMNS];
Zp t[NUM_REPETITIONS][NUM_COLUMNS];
GT Z[NUM_REPETITIONS][NUM_COLUMNS];
G1 HashedRound;
GT e;
bool Challenge[NUM_REPETITIONS];

#if PARALLELISM == 1
CycGrpZp sk_parallel_safe[NUM_REPETITIONS];
GT e_parallel_safe[NUM_REPETITIONS];
#endif
generate_secret_key(&P->sk);
generate_public_key(&P->PK,&P->sk);
#if PARALLELISM == 1

for (i=0;i<NUM_REPETITIONS;i++) CycGrpZp_copy(&sk_parallel_safe[i],&P->sk); 
#pragma omp parallel 
{
#pragma omp for
#endif
for (i=0;i<NUM_REPETITIONS;i++){ 
CycGrpZp_setRand(&sk[i][0]);

Zp_setRand(&t[i][0]);
Zp_setRand(&t[i][1]);

#if PARALLELISM == 1
CycGrpZp_sub(&sk[i][1],&sk_parallel_safe[i], &sk[i][0]);
#else
CycGrpZp_sub(&sk[i][1],&P->sk, &sk[i][0]);
#endif
CycGrpG_mul(&P->pi.C[i][0].PK,&CycGrpGenerator,&sk[i][0]); // PK[i][0]=g^{sk[i][0]}
CycGrpG_mul(&P->pi.C[i][1].PK,&CycGrpGenerator,&sk[i][1]);

G2_mul(&P->pi.C[i][0].T,&G2Generator,&t[i][0]); // T[i][0]=g2^{t[i][0]} 
G2_mul(&P->pi.C[i][1].T,&G2Generator,&t[i][1]);
}
#if PARALLELISM == 1
}
#endif
HashRoundToG1(&HashedRound,&round); // HashedRound=SHA256(round)
pairing(&e,&HashedRound,&SIM_PK_LOE); // compute e=e(H(round),SIM_PK_LOE)

#if PARALLELISM == 1
for (i=0;i<NUM_REPETITIONS;i++) GT_copy(&e_parallel_safe[i],&e);
#pragma omp parallel
{
#pragma omp for
#endif
for (i=0;i<NUM_REPETITIONS;i++){ 
 /* powers the previously precomputed element e to t[i][0], t[i][1] 
to compute the resp. elements Z[i][0], Z[i][1]
for all i=0,..., NUM_REPETITIONS-1  
*/
#if PARALLELISM == 1
GT_pow(&Z[i][0],&e_parallel_safe[i],  &t[i][0]);
GT_pow(&Z[i][1],&e_parallel_safe[i],  &t[i][1]);
#else
GT_pow(&Z[i][0],&e,  &t[i][0]);
GT_pow(&Z[i][1],&e,  &t[i][1]);
#endif
// now we hash  the Z[i][0], Z[i][1] and XOR them with the sk[i][0] ,sk[i][1] to compute the y[i][0],y[i][1]

#if PARALLELISM == 1
HashGTToBytes(buf_for_hashing_parallel_safe[i],&Z[i][0]); // buf_for_hashing holds SHA256(Z[i][0])
XOR(P->pi.C[i][0].y,&sk[i][0],buf_for_hashing_parallel_safe[i]); // y[i]= sk[i][0] XOR SHA256(Z[i][0])
HashGTToBytes(buf_for_hashing_parallel_safe[i],&Z[i][1]);
XOR(P->pi.C[i][1].y,&sk[i][1],buf_for_hashing_parallel_safe[i]); 
#else
HashGTToBytes(buf_for_hashing,&Z[i][0]); // buf_for_hashing holds SHA256(Z[i][0])
XOR(P->pi.C[i][0].y,&sk[i][0],buf_for_hashing); // y[i]= sk[i][0] XOR SHA256(Z[i][0])
HashGTToBytes(buf_for_hashing,&Z[i][1]);
XOR(P->pi.C[i][1].y,&sk[i][1],buf_for_hashing); 
#endif
}
#if PARALLELISM == 1
}
#endif
ComputeChallenge(Challenge,&P->PK,P->pi.C,&round);
#if PARALLELISM == 1
#pragma omp parallel
{
#pragma omp for
#endif
for (i=0;i<NUM_REPETITIONS;i++){
CycGrpZp_copy(&P->pi.O[i].sk,&sk[i][Challenge[i]]);
// uncomment this as sanity check
//if (i==0) CycGrpZp_copy(&P->pi.O[i].t,&t[i+1][Challenge[i]]);
// else 
 CycGrpZp_copy(&P->pi.O[i].t,&t[i][Challenge[i]]);
}
#if PARALLELISM == 1
}
#endif

return 0;
}
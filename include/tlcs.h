// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _TLCS_H_
#define _TLCS_H_ 1
#include <stdint.h>
 #include <openssl/sha.h>
#include <mcl/bn_c384_256.h>
#include "cyclic_group.h"
#define NUM_REPETITIONS 80
#define NUM_COLUMNS 2
extern int g_err;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }
extern unsigned char buf_for_serializing[1024]; 
extern unsigned char buf_for_hashing[SHA256_DIGEST_LENGTH]; 
#if PARALLELISM ==1 
extern unsigned char buf_for_hashing_parallel_safe[NUM_REPETITIONS][SHA256_DIGEST_LENGTH]; 
#endif 


typedef struct {
G2 T;
CycGrpG PK;
unsigned char y[SHA256_DIGEST_LENGTH];

} CommitmentTuple;
typedef struct{
Zp sk;
CycGrpZp t;
} OpeningTuple;
typedef struct {
CommitmentTuple C[NUM_REPETITIONS][NUM_COLUMNS];
OpeningTuple O[NUM_REPETITIONS];
} Proof;

typedef struct {
CycGrpZp sk;
CycGrpG PK;
Proof pi;
} TLCSParty;


void err(void);
int Prover(TLCSParty *P,uint64_t round);
int Verifier(CycGrpG *PK,Proof *P,uint64_t round);
int Invert(CycGrpZp *sk,CycGrpG *PK,G1 *Signature, Proof *pi);
int InvertAggregate(CycGrpZp *gsk,TLCSParty P[],size_t num_parties,G1 *Signature,bool verified_proof[]);
void AggregatePublicKeys(CycGrpG *GPK,TLCSParty P[],size_t num_parties, bool verified_proof[]);
void ComputeChallenge(bool Challenge[],CycGrpG *PK,CommitmentTuple C[][NUM_COLUMNS],uint64_t *round);
void XOR(unsigned char y[], CycGrpZp *sk, unsigned char sha256_digest[]);
void XOR_Verifier(CycGrpZp *sk, unsigned char HashZ[], unsigned char y[]);
int HashGTToBytes(unsigned char *buf,GT *e);
void HashRoundToG1(G1 *g1,uint64_t *round);
#endif 
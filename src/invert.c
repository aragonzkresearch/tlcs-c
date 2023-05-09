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
int Invert(CycGrpZp *sk,CycGrpG *PK,G1 *Signature, Proof *pi){
int i,b;
GT Z;
CycGrpZp sktmp;
CycGrpG GTmp;
CycGrpZp s[NUM_COLUMNS];
#if CYC_GRP_BLS_G1 == 1
#else
CycGrpG_new(&GTmp);
CycGrpZp_new(&s[0]);
CycGrpZp_new(&s[1]);
CycGrpZp_new(&sktmp);
#endif

for (i=0;i<NUM_REPETITIONS;i++){ 

CycGrpG_add(&GTmp,&pi->C[i][0].PK,&pi->C[i][1].PK);
if (!CycGrpG_isEqual(&GTmp,PK)){
#if _DEBUG_ == 1
printf("Invert: error1 in repetition %d\n",i);
#endif
return 1; 
}

for (b=0;b<NUM_COLUMNS;b++){

pairing(&Z,Signature,&pi->C[i][b].T); // compute Z=e(Signature,T[i][b])
// now we hash  the value Z and XOR them with the y[i][b] 
HashGTToBytes(buf_for_hashing,&Z); // buf_for_hashing holds SHA256(Z)
XOR_Verifier(&s[b],pi->C[i][b].y,buf_for_hashing); // s[b]= y[i][b] XOR SHA256(Z])
}
CycGrpZp_add(&sktmp,&s[0],&s[1]);
#if CYC_GRP_BLS_G1 == 1
CycGrpG_mul(&GTmp,&CycGrpGenerator,&sktmp);
#else
CycGrpG_mul(&GTmp,CycGrpGenerator,&sktmp);
#endif
if (!CycGrpG_isEqual(&GTmp,PK)) { // check that g^s =PK[i]
#if _DEBUG_ == 1
printf("Invert: error2 in repetition %d\n",i);
#endif
return 1;
}
else {
CycGrpZp_copy(sk,&sktmp);
#if _DEBUG_ == 1
printf("party' sk found out in repetition %d\n",i);
#endif
return 0;
}
}

return 1;
}



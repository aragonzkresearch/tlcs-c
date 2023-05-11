// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"


char *SerializePartyOutput(const CycGrpG *PK,const Proof *pi,size_t *size){
char *s=(char *)malloc(1000000);
char *tmps;
int i,j;
size_t len=0,tmplen;
// serialize PK
tmps=CycGrpG_toHexString(PK);
//printf("PK: %s\n",tmps);
tmplen=strlen(tmps);
strcpy(s,tmps);
len+=tmplen+1;
//free(tmps);


for (i=0;i<NUM_REPETITIONS;i++) //serialize CommitmentTuples
for (j=0;j<NUM_COLUMNS;j++) {
tmps=G2_toHexString(&pi->C[i][j].T); // serialize C[i][j].T
//printf("T[%d]: %s\n",j,tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);

tmps=CycGrpG_toHexString(&pi->C[i][j].PK); // serialize C[i][j].PK
//printf("PK[%d]: %s\n",j,tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);

memcpy(s+len,(char *)pi->C[i][j].y,SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO); // serialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",*((unsigned char *)s+len+k));
printf("\n");
}*/
len+=SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO;

}

for (i=0;i<NUM_REPETITIONS;i++){ //serialize OpeningTuples
/*
tmps=CycGrpZp_toHexString(&pi->O[i].sk); // serialize O[i].sk
printf("opened sk: %s\n",tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);
*/
tmps=Zp_toHexString(&pi->O[i].t); // serialize O[i].t
//printf("t[%d]: %s\n",i,tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);

}
//printf("length string: %d\n",(int) len);
//write(2,s,len);
if (size!=NULL) *size=len;
return s;
}



void DeserializePartyOutput(CycGrpG *PK,Proof *pi,const char *buf,size_t *size){
int i,j;
char *s=(char *)buf;
// deserialize PK
#if CYC_GRP_BLS_G1 == 1
#else
CycGrpG_new(PK);
#endif
CycGrpG_fromHexString(PK,s);
//printf("deserialized PK: %s\n",CycGrpG_toHexString(PK));
s+=strlen(s)+1;

for (i=0;i<NUM_REPETITIONS;i++) //deserialize CommitmentTuples
for (j=0;j<NUM_COLUMNS;j++) {
G2_fromHexString(&pi->C[i][j].T,s); // deserialize C[i][j].T
//printf("deserialized T[%d]: %s\n",j,G2_toHexString(&pi->C[i][j].T));
s+=strlen(s)+1;

#if CYC_GRP_BLS_G1 == 1
#else
CycGrpG_new(&pi->C[i][j].PK);
#endif
CycGrpG_fromHexString(&pi->C[i][j].PK,s); // deserialize C[i][j].PK
//printf("deserialized PK[%d]: %s\n",j,CycGrpG_toHexString(&pi->C[i][j].PK));
s+=strlen(s)+1;

memcpy((char *)pi->C[i][j].y,s,SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO); // deserialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",(unsigned char)pi->C[i][j].y[k]);
//printf("\n");
}*/
s+=SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO;
}

for (i=0;i<NUM_REPETITIONS;i++){ // deserialize OpeningTuples
/*
#if CYC_GRP_BLS_G1 == 1
#else
CycGrpZp_new(&pi->O[i].sk);
#endif
CycGrpZp_fromHexString(&pi->O[i].sk,s); // deserialize O[i].sk
printf("deserialized opened sk: %s\n",CycGrpZp_toHexString(&pi->O[i].sk));
s+=strlen(s)+1;
*/
Zp_fromHexString(&pi->O[i].t,s); // deserialize O[i].t
//printf("opened t[%d]: %s\n",i,Zp_toHexString(&pi->O[i].t));
s+=strlen(s)+1;

}
if (size != NULL) *size=s-buf;
}















char *SerializePKandCommitment(const CycGrpG *PK,const CommitmentTuple C[][NUM_COLUMNS]){
char *s=(char *)malloc(1000000);
char *tmps;
int i,j;
size_t len=0,tmplen;
// serialize PK
tmps=CycGrpG_toHexString(PK);
//printf("PK: %s\n",tmps);
tmplen=strlen(tmps);
strcpy(s,tmps);
len+=tmplen+1;
//free(tmps);


for (i=0;i<NUM_REPETITIONS;i++) //serialize CommitmentTuples
for (j=0;j<NUM_COLUMNS;j++) {
tmps=G2_toHexString(&C[i][j].T); // serialize C[i][j].T
//printf("T[%d]: %s\n",j,tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);

tmps=CycGrpG_toHexString(&C[i][j].PK); // serialize C[i][j].PK
//printf("PK[%d]: %s\n",j,tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);

memcpy(s+len,(char *)C[i][j].y,SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO); // serialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",*((unsigned char *)s+len+k));
printf("\n");
}*/
len+=SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO;

}

//printf("length string: %d\n",(int) len);
//write(2,s,len);
return s;
}

// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"


#if CYC_GRP_BLS_G1 == 1
CycGrpG CycGrpGenerator;
static const char *g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

int group_init(void){
int ret=CycGrpG_setStr(&CycGrpGenerator, g1Str, strlen(g1Str), 16);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
		return 1;
	}
return 0;
}
void generate_public_key(CycGrpG *PK,const CycGrpZp *sk){
CycGrpG_mul(PK, &CycGrpGenerator, sk);

}
void generate_secret_key(CycGrpZp *sk){
ASSERT(!CycGrpZp_setRand(sk));
}
#else // if undefined or set to any other string then we use openssl EC
CycGrpG *CycGrpGenerator;
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
BN_CTX *bn_ctx;
	EC_GROUP *ec_group=NULL;
CycGrpZp Order;
int Order_bits;
int group_init(int curve_type){
ec_group = EC_GROUP_new_by_curve_name(curve_type);
	if (ec_group == NULL) {
		printf("err in initialiting the group\n");
		return 1;
	}
CycGrpGenerator=(CycGrpG *)malloc(sizeof(CycGrpG));
CycGrpGenerator->P=EC_POINT_new(ec_group);

EC_POINT_copy(CycGrpGenerator->P,EC_GROUP_get0_generator(ec_group));
bn_ctx=BN_CTX_new();

Order.B=BN_new();
if (!EC_GROUP_get_order(ec_group,Order.B,NULL)) return 1;
Order_bits=BN_num_bits(Order.B);

return 0;
}
void generate_public_key(CycGrpG *PK,const CycGrpZp *sk){
CycGrpG_new(PK); 
CycGrpG_mul(PK, CycGrpGenerator, sk);

}

void generate_secret_key(CycGrpZp *sk){
CycGrpZp_new(sk);
ASSERT(!CycGrpZp_setRand(sk));
}

#endif

void CycGrpZp_copy(CycGrpZp *a,const CycGrpZp *b){
#if PARALLELISM == 1
unsigned char buf_parallel_safe[1024];
CycGrpZp_serialize(buf_parallel_safe,sizeof(buf_parallel_safe),b); 
CycGrpZp_deserialize(a, buf_parallel_safe,sizeof(buf_parallel_safe)); 
#else
CycGrpZp_serialize(buf_for_serializing,sizeof(buf_for_serializing),b); 
CycGrpZp_deserialize(a, buf_for_serializing,sizeof(buf_for_serializing)); 
#endif
}
void CycGrpG_copy(CycGrpG *a,const CycGrpG *b){

CycGrpG_serialize(buf_for_serializing,sizeof(buf_for_serializing),b); 
CycGrpG_deserialize(a, buf_for_serializing,sizeof(buf_for_serializing)); 
}

char* CycGrpZp_toHexString(const CycGrpZp *a){
char *s;
#if CYC_GRP_BLS_G1 == 1
char buf[1024];
size_t len;
len=mclBnFr_getStr(buf, 1024, a, 16);
s=(char *)malloc(len+1);
strncpy(s,buf,len);
s[len]='\0';
#else
s=BN_bn2hex(a->B);
#endif
return s;
}

void CycGrpZp_fromHexString(CycGrpZp *x,const char *s){
//CycGrpZp_deserialize(x,(unsigned char *)s,strlen(s));
#if CYC_GRP_BLS_G1 == 1
mclBnFr_setStr(x,s,strlen(s),16);
#else
CycGrpZp_deserialize(x,(unsigned char *)s,strlen(s));
#endif
}

char* CycGrpG_toHexString(const CycGrpG *a){
char *s;
#if CYC_GRP_BLS_G1 == 1
char buf[1024];
size_t len;
len=mclBnG1_getStr(buf, 1024, a, 16);
s=(char *)malloc(len+1);
strncpy(s,buf,len);
s[len]='\0';
#else
s=EC_POINT_point2hex(ec_group,a->P,POINT_CONVERSION_COMPRESSED,NULL);
#endif
return s;
}
void CycGrpG_fromHexString(CycGrpG *g,const char *s){
//CycGrpG_deserialize(g,(unsigned char *)s,strlen(s));
#if CYC_GRP_BLS_G1 == 1
mclBnG1_setStr(g,s,strlen(s),16);
#else
CycGrpG_deserialize(g,(unsigned char *)s,strlen(s));
#endif
}

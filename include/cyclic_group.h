// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _CYCGRP_H_
#define _CYCGRP_H_ 1
#include "pairing.h"
#if CYC_GRP_BLS_G1 == 1
#define CycGrpG_mul(h,g,x) (G1_mul(h,g,x))
#define CycGrpG_isEqual(h,g) (G1_isEqual(h,g))
#define CycGrpZp_isEqual(x,y) (Zp_isEqual(x,y))
#define CycGrpG_add(h,u,v) (G1_add(h,u,v))
#define CycGrpZp_add(z,x,y) (Zp_add(z,x,y))
#define CycGrpZp_sub(z,x,y) (Zp_sub(z,x,y))
#define CycGrpZp_setRand(x) (Zp_setRand(x))
#define CycGrpG_setStr(g,gStr,len_gStr,base) (G1_setStr(g,gStr,len_gStr,base))
#define CycGrpZp_serialize(buf,maxBufSize,x) (Zp_serialize(buf,maxBufSize,x))
#define CycGrpG_serialize(buf,maxBufSize,g) (G1_serialize(buf,maxBufSize,g))
#define CycGrpZp_deserialize(x,buf,maxBufSize) (Zp_deserialize(x,buf,maxBufSize))
#define CycGrpG_deserialize(g,buf,maxBufSize) (G1_deserialize(g,buf,maxBufSize))
//typedef struct {
//mclBnG1 g1;
//} CycGrpG;
//typedef mclBnG1 CycGrpG;
#define CycGrpG mclBnG1
#define CycGrpZp mclBnFr
//typedef mclBnG1 CycGrpG;
//typedef mclBnFr CycGrpZp;
int group_init(void);
extern CycGrpG CycGrpGenerator;
#else
#include <string.h>
#include <openssl/ec.h>
extern BN_CTX *bn_ctx;
int group_init(int type);
	extern EC_GROUP *ec_group;

typedef struct { EC_POINT *P;} CycGrpG;
typedef struct { BIGNUM *B; } CycGrpZp;
extern CycGrpZp Order;
extern int Order_bits;
// NOTE: deserialize and serialize bot for CycGrpG and CycGrpZp may behave differently accordingly on whether CYC_GRG_BLS_G1= 1 or 0. 
// Currently _serialize functions work exactly as _toHexStr functions but we keep it separate in view of future changes (e.g., serialize to binary to improve efficiency).
inline void CycGrpG_deserialize(CycGrpG *g,const unsigned char *buf,size_t maxBufSize) { EC_POINT_hex2point(ec_group,(const char*)buf,g->P,NULL); } 
inline void CycGrpG_serialize(unsigned char *buf,size_t maxBufSize,const CycGrpG *g) { 
strcpy((char *)buf,(char *)EC_POINT_point2hex(ec_group,g->P,POINT_CONVERSION_COMPRESSED,NULL)); 
}
inline int CycGrpZp_isEqual(const CycGrpZp *x,const CycGrpZp *y) { return !BN_cmp(x->B,y->B); }
// TODO: switch the return values (this will affect the code of prover, verifier, aggregator and inversion)
inline void CycGrpZp_add(CycGrpZp *z,const CycGrpZp *x,const CycGrpZp *y) { BN_mod_add(z->B,x->B,y->B,Order.B,bn_ctx); }
inline int  CycGrpG_isEqual(const CycGrpG *h,const CycGrpG *g) { return !EC_POINT_cmp(ec_group,(h)->P,(g)->P,NULL); } // we return 1 on success if both points are equal for compatibility with mcl isEqual and similar functions
inline void CycGrpG_add(CycGrpG *h,const CycGrpG *u,const CycGrpG *v) { EC_POINT_add(ec_group,h->P,u->P,v->P,NULL); }
inline void CycGrpZp_sub(CycGrpZp *z,const CycGrpZp *x,const CycGrpZp *y) { 
BN_mod_sub(z->B,x->B,y->B,Order.B,bn_ctx); 
}
inline void CycGrpG_mul(CycGrpG *h,const CycGrpG *g,const CycGrpZp *x) { EC_POINT_mul(ec_group,h->P,NULL,g->P,x->B,NULL); }
inline void CycGrpZp_serialize(unsigned char *buf,size_t maxBufSize,const CycGrpZp *x) { strcpy((char *)buf,(char *)BN_bn2hex(x->B)); } // TODO: handle in binary formats. This would require to redefine the CycGrpZp type to store the length of the element to serialize/deserialize
inline int CycGrpZp_setRand(CycGrpZp *x){ BN_rand(x->B,Order_bits,0,Order_bits-1); return 0; }
inline void CycGrpZp_deserialize(CycGrpZp *x,unsigned const char *buf,size_t len){ BN_hex2bn(&(x->B),(const char *)buf); }
inline void CycGrpG_new(CycGrpG *g) { g->P=EC_POINT_new(ec_group); }
inline void CycGrpZp_new(CycGrpZp *x) { x->B=BN_new(); }
extern CycGrpG *CycGrpGenerator;
#endif
void CycGrpZp_copy(CycGrpZp *a,const CycGrpZp *b);
void CycGrpG_copy(CycGrpG *a,const CycGrpG *b);
char* CycGrpZp_toHexString(const CycGrpZp *a); // convert point in Hex string. When CYC_GRP_BLS_G1=1 the representation is like the one described here:
// https://github.com/herumi/mcl/blob/master/api.md for ioMode=16. Otherwise, it uses the serialization of openssl. The strings are always terminated by the null character '\0'.
char* CycGrpG_toHexString(const CycGrpG *a);
void CycGrpZp_fromHexString(CycGrpZp *x,const char *s);
void CycGrpG_fromHexString(CycGrpG *a,const char *s);
void generate_secret_key(CycGrpZp *sk);
void generate_public_key(CycGrpG *PK,const CycGrpZp*sk);
#endif 

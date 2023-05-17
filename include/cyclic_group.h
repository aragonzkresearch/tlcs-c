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
int group_init (void);
extern CycGrpG CycGrpGenerator;
#else
#include <string.h>
#include <openssl/ec.h>
extern BN_CTX *bn_ctx;
extern int Order_bits;
#if CYC_GRP_RSA == 1
int group_init (const char *RSA_modulus, const char *RSA_pk);
#else
extern int bjj_flag;		// we set to 1 if we use babyjubjub
int TwistedEdwards2Weierstrass (char *W, const char *E);
void Weierstrass2TwistedEdwards (char *E, const char *W);
int group_init (int type);
#endif
extern EC_GROUP *ec_group;

typedef struct
{
#if CYC_GRP_RSA == 1
  BIGNUM *P;
#else
  EC_POINT *P;
#endif
} CycGrpG;
typedef struct
{
  BIGNUM *B;
} CycGrpZp;
#if CYC_GRP_RSA == 1
extern BIGNUM *RSA_modulus;
extern BIGNUM *RSA_pk;
#else
extern CycGrpZp Order;
#endif
// NOTE: deserialize and serialize bot for CycGrpG and CycGrpZp may behave differently accordingly on whether CYC_GRG_BLS_G1= 1 or 0. 
// Currently _serialize functions work exactly as _toHexStr functions but we keep it separate in view of future changes (e.g., serialize to binary to improve efficiency).
inline int
CycGrpG_deserialize (CycGrpG * g, const unsigned char *buf, size_t maxBufSize)	// hex2point return 0 on error and 1 on success but we return 0 on success and -1 on error
{
#if CYC_GRP_RSA == 1
  if (!BN_hex2bn (&g->P, (const char *) buf))
    return -1;
  return 0;
#else
  if (!EC_POINT_hex2point (ec_group, (const char *) buf, g->P, NULL))
    return -1;
  return 0;
#endif
}

inline void
CycGrpG_serialize (unsigned char *buf, size_t maxBufSize, const CycGrpG * g)
{
#if CYC_GRP_RSA == 1
  strcpy ((char *) buf, (char *) BN_bn2hex (g->P));
#else
  strcpy ((char *) buf,
	  (char *) EC_POINT_point2hex (ec_group, g->P,
				       POINT_CONVERSION_COMPRESSED, NULL));
#endif
}

inline int
CycGrpZp_isEqual (const CycGrpZp * x, const CycGrpZp * y)	// same for EC and RSA
{
  return !BN_cmp (x->B, y->B);
}

// TODO: switch the return values (this will affect the code of prover, verifier, aggregator and inversion)
inline void
CycGrpZp_add (CycGrpZp * z, const CycGrpZp * x, const CycGrpZp * y)
{
#if CYC_GRP_RSA == 1
  BN_mod_mul (z->B, x->B, y->B, RSA_modulus, bn_ctx);
#else
  BN_mod_add (z->B, x->B, y->B, Order.B, bn_ctx);
#endif
}

inline int
CycGrpG_isEqual (const CycGrpG * h, const CycGrpG * g)
{
#if CYC_GRP_RSA == 1
  return !BN_cmp (h->P, g->P);
#else
  return !EC_POINT_cmp (ec_group, h->P, g->P, NULL);
#endif
}				// we return 1 on success if both points are equal for compatibility with mcl isEqual and similar functions

inline void
CycGrpG_add (CycGrpG * h, const CycGrpG * u, const CycGrpG * v)
{
#if CYC_GRP_RSA == 1
  BN_mod_mul (h->P, u->P, v->P, RSA_modulus, bn_ctx);
#else
  EC_POINT_add (ec_group, h->P, u->P, v->P, NULL);
#endif
}

inline void
CycGrpZp_sub (CycGrpZp * z, const CycGrpZp * x, const CycGrpZp * y)
{
#if CYC_GRP_RSA == 1
  BIGNUM *tmp;
  tmp = BN_new ();
  BN_copy (tmp, y->B);
  BN_mod_inverse (tmp, tmp, RSA_modulus, bn_ctx);
  BN_mod_mul (z->B, x->B, tmp, RSA_modulus, bn_ctx);
  BN_free (tmp);
#else
  BN_mod_sub (z->B, x->B, y->B, Order.B, bn_ctx);
#endif
}

inline void
CycGrpG_mul (CycGrpG * h, const CycGrpG * g, const CycGrpZp * x)	// in case of RSA g is ignored. In the EC case g is always the generator of the group
{
#if CYC_GRP_RSA == 1
  BN_mod_exp (h->P, x->B, RSA_pk, RSA_modulus, bn_ctx);
#else
  EC_POINT_mul (ec_group, h->P, NULL, g->P, x->B, NULL);
#endif
}

inline void
CycGrpZp_serialize (unsigned char *buf, size_t maxBufSize, const CycGrpZp * x)
{
  strcpy ((char *) buf, (char *) BN_bn2hex (x->B));
}				// TODO: handle in binary formats. This would require to redefine the CycGrpZp type to store the length of the element to serialize/deserialize

inline int
CycGrpZp_setRand (CycGrpZp * x)
{
  BN_rand (x->B, Order_bits, 0, Order_bits - 1);
  return 0;
}

inline int
CycGrpZp_deserialize (CycGrpZp * x, unsigned const char *buf, size_t len)	// hex2bin return 0 on error and 1 on success but we return 0 on success and -1 otherwise
{
  if (!BN_hex2bn (&(x->B), (const char *) buf))
    return -1;
  return 0;
}

inline void
CycGrpG_new (CycGrpG * g)
{
#if CYC_GRP_RSA == 1
  g->P = BN_new ();
#else
  g->P = EC_POINT_new (ec_group);
#endif
}

inline void
CycGrpZp_new (CycGrpZp * x)
{
  x->B = BN_new ();
}

extern CycGrpG *CycGrpGenerator;
EC_GROUP *babyjubjub_init (void);
#endif
void CycGrpZp_copy (CycGrpZp * a, const CycGrpZp * b);
void CycGrpG_copy (CycGrpG * a, const CycGrpG * b);
char *CycGrpZp_toHexString (const CycGrpZp * a);	// convert point in Hex string. When CYC_GRP_BLS_G1=1 the representation is like the one described here:
// https://github.com/herumi/mcl/blob/master/api.md for ioMode=16. Otherwise, it uses the serialization of openssl. The strings are always terminated by the null character '\0'.
char *CycGrpG_toHexString (const CycGrpG * a);
char *CycGrpG_toHexStringUncompressed (const CycGrpG * a);
int CycGrpZp_fromHexString (CycGrpZp * x, const char *s);
int CycGrpG_fromHexString (CycGrpG * a, const char *s);
void generate_secret_key (CycGrpZp * sk);
void generate_public_key (CycGrpG * PK, const CycGrpZp * sk);
#endif

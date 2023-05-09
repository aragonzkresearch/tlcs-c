// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _PAIRING_H_
#define _PAIRING_H_ 1
//#include <mcl/bn_c384_256.h>
typedef mclBnG1 G1;
typedef mclBnG2 G2;
typedef mclBnGT GT;
typedef mclBnFr Zp;

extern G2 G2Generator;
int pairing_init(void);
void  GT_copy(GT *a,GT *b);
#define Zp_serialize(buf,maxBufSize,x) (mclBnFr_serialize(buf,maxBufSize,x))
#define G1_serialize(buf,maxBufSize,g) (mclBnG1_serialize(buf,maxBufSize,g))
#define Zp_deserialize(x,buf,maxBufSize) (mclBnFr_deserialize(x,buf,maxBufSize))
#define G1_deserialize(g,buf,maxBufSize) (mclBnG1_deserialize(g,buf,maxBufSize))
#define G1_setStr(g1,g1Str,len_g1Str,base) (mclBnG1_setStr(g1,g1Str,len_g1Str,base))
#define G2_setStr(g2,g2Str,len_g2Str,base) (mclBnG2_setStr(g2,g2Str,len_g2Str,base))
#define Zp_setRand(x) (mclBnFr_setByCSPRNG(x))
#define Zp_add(z,x,y) (mclBnFr_add(z,x,y))
#define Zp_sub(z,x,y) (mclBnFr_sub(z,x,y))
#define G1_mul(h, g1, x) (mclBnG1_mul(h, g1, x))
#define G2_mul(h, g2, x) (mclBnG2_mul(h, g2, x))
#define G1_add(h, u, v) (mclBnG1_add(h, u, v))
#define GT_pow(e, gt, x) (mclBnGT_pow(e, gt, x))
#define G1_isEqual(h, u) (mclBnG1_isEqual(h, u))
#define G2_isEqual(h, u) (mclBnG2_isEqual(h, u))
#define Zp_isEqual(h, u) (mclBnFr_isEqual(h, u))
#define GT_isEqual(e1, e2) (mclBnGT_isEqual(e1, e2))
#define G1_hashAndMapTo(g1,buf,bufSize) (mclBnG1_hashAndMapTo(g1, buf, bufSize))
#define pairing(e,g1,g2) (mclBn_pairing(e,g1,g2))
#define GT_serialize(buf,len,e) (mclBnGT_serialize(buf,len,e))
#define GT_deserialize(e,buf,len) (mclBnGT_deserialize(e,buf,len))
extern unsigned char buf_for_serializing[1024];
inline void Zp_copy(Zp *a,Zp *b){
#if PARALLELISM == 1
unsigned char buf_parallel_safe[1024];
Zp_serialize(buf_parallel_safe,sizeof(buf_parallel_safe),b); 
Zp_deserialize(a, buf_parallel_safe,sizeof(buf_parallel_safe)); 
#else
Zp_serialize(buf_for_serializing,sizeof(buf_for_serializing),b); 
Zp_deserialize(a, buf_for_serializing,sizeof(buf_for_serializing)); 
#endif
}
#endif

// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#ifndef _CYCGRP_H_
#define _CYCGRP_H_ 1
#include "pairing.h"
#define CycGrpG_mul(h,g,x) (G1_mul(h,g,x))
#define CycGrpG_isEqual(h,g) (G1_isEqual(h,g))
#define CycGrpZp_isEqual(h,g) (Zp_isEqual(h,g))
#define CycGrpG_add(h,u,v) (G1_add(h,u,v))
#define CycGrpZp_add(h,u,v) (Zp_add(h,u,v))
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
typedef mclBnG1 CycGrpG;
typedef mclBnFr CycGrpZp;
void CycGrpZp_copy(CycGrpZp *a,CycGrpZp *b);
void CycGrpG_copy(CycGrpG *a,CycGrpG *b);
void generate_secret_key(CycGrpZp *sk);
void generate_public_key(CycGrpG *PK,const CycGrpZp*sk);
extern CycGrpG CycGrpGenerator;
int group_init(void);
#endif 

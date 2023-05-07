// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
 #include <openssl/sha.h>
#include "tlcs.h"

G2 G2Generator;
const char *g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
int pairing_init(void){
int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
		return 1;
	}
ret=G2_setStr(&G2Generator, g2Str, strlen(g2Str), 16);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
		return 1;
	}
return 0;
}

void  GT_copy(GT *a,GT *b){
#if PARALLELISM == 1
unsigned char buf_parallel_safe[1024];
GT_serialize(buf_parallel_safe,sizeof(buf_parallel_safe),b); 
GT_deserialize(a, buf_parallel_safe,sizeof(buf_parallel_safe)); 
#else
GT_serialize(buf_for_serializing,sizeof(buf_for_serializing),b); 
GT_deserialize(a, buf_for_serializing,sizeof(buf_for_serializing)); 
#endif
}

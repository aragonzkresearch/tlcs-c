// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"
G2 PK_LOE;
static const char *PK_LOEStr="a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
static Zp sk;
void generate_loe_publickey(void){
#if PK_SIMULATED == 1
ASSERT(!Zp_setRand(&sk));
G2_mul(&PK_LOE, &G2Generator, &sk);
#else
mclBn_setETHserialization(1);
ASSERT(!(mclBnG2_setStr(&PK_LOE, PK_LOEStr, strlen(PK_LOEStr), MCLBN_IO_SERIALIZE_HEX_STR)));
mclBn_setETHserialization(0);
#endif
}
void generate_loe_signature(G1 *Signature, uint64_t round){
G1 Hash;
HashRoundToG1(&Hash,&round); // HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))
G1_mul(Signature,&Hash,&sk);
}

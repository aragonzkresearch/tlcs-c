// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdint.h>
#include <stdio.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"
G2 SIM_PK_LOE;
static Zp sk;
void generate_loe_publickey(void){
ASSERT(!Zp_setRand(&sk));
G2_mul(&SIM_PK_LOE, &G2Generator, &sk);

}
void generate_loe_signature(G1 *Signature, uint64_t round){
G1 Hash;
HashRoundToG1(&Hash,&round); // HashedRound=SHA256(round)
G1_mul(Signature,&Hash,&sk);
}

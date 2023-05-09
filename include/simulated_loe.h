// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <time.h>
extern time_t loe_genesis_time;
extern unsigned int loe_period;
extern G2 PK_LOE;
void generate_loe_publickey(void);
void generate_loe_signature(G1 *Signature, uint64_t round);

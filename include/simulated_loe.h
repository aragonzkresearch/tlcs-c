// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// For LICENSE check https://github.com/aragonzkresearch/ovote/blob/master/LICENSE
// Vincenzo Iovino, 2023, Aragon ZK Research
extern G2 SIM_PK_LOE;
void generate_loe_publickey(void);
void generate_loe_signature(G1 *Signature, uint64_t round);

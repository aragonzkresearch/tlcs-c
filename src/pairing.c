// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
#include <openssl/sha.h>
#include "tlcs.h"

G2 G2Generator;
//const char *g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
const char *g2Str =
  "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582";
const char *dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";	// LOE incorrectly uses this domain also for hashing to G2. They acknowledged the bug but for compatibility it must stay unchainged.
int
pairing_init (void)
{
  int ret = mclBn_init (MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
  if (ret != 0)
    {
      printf ("err ret=%d\n", ret);
      return 1;
    }
  ret = G2_setStr (&G2Generator, g2Str, strlen (g2Str), 10);
  if (ret != 0)
    {
      printf ("err ret=%d\n", ret);
      return 1;
    }
  mclBn_setMapToMode (MCL_MAP_TO_MODE_HASH_TO_CURVE);
  mclBnG1_setDst (dst, strlen (dst));
  return 0;
}

void
GT_copy (GT * a, GT * b)
{
#if PARALLELISM == 1
  unsigned char buf_parallel_safe[MAX_LENGTH_SERIALIZATION];
  GT_serialize (buf_parallel_safe, MAX_LENGTH_SERIALIZATION, b);
  GT_deserialize (a, buf_parallel_safe, MAX_LENGTH_SERIALIZATION);
#else
  GT_serialize (buf_for_serializing, MAX_LENGTH_SERIALIZATION, b);
  GT_deserialize (a, buf_for_serializing, MAX_LENGTH_SERIALIZATION);
#endif
}

char *
G1_toHexString (const G1 * g)
{
  char buf[MAX_LENGTH_SERIALIZATION];
  char *s;
//int len=G2_serialize(buf,MAX_LENGTH_SERIALIZATION,g);
  mclBn_setETHserialization (1);
  int len = mclBnG1_getStr (buf, MAX_LENGTH_SERIALIZATION, g, 16);
  if (len == 0)
    {
      mclBn_setETHserialization (0);
      return NULL;
    }
  s = (char *) malloc (len + 1);
  strncpy (s, buf, len);
  s[len] = '\0';
  mclBn_setETHserialization (0);
  return s;
}

char *
G2_toHexString (const G2 * g)
{
  char buf[MAX_LENGTH_SERIALIZATION];
  char *s;
//int len=G2_serialize(buf,MAX_LENGTH_SERIALIZATION,g);
  mclBn_setETHserialization (1);
  int len = mclBnG2_getStr (buf, MAX_LENGTH_SERIALIZATION, g,
			    MCLBN_IO_SERIALIZE_HEX_STR);
  if (len == 0)
    {
      mclBn_setETHserialization (0);
      return NULL;
    }
  s = (char *) malloc (len + 1);
  //strncpy (s, buf, len);
  memcpy (s, buf, len);
  s[len] = '\0';
  mclBn_setETHserialization (0);
  return s;
}

int
G2_fromHexString (G2 * g, const char *s)
{
  int ret;
//G2_deserialize(g,s,strlen(s));
  mclBn_setETHserialization (1);
  ret = mclBnG2_setStr (g, s, strlen (s), MCLBN_IO_SERIALIZE_HEX_STR);
  //mclBnG2_deserialize (g, s,MAX_LENGTH_SERIALIZATION);
  mclBn_setETHserialization (0);
  return ret;
}

char *
Zp_toHexString (const Zp * x)
{
  char buf[MAX_LENGTH_SERIALIZATION];
  char *s;
//int len=Zp_serialize((unsigned char *)buf,MAX_LENGTH_SERIALIZATION,x);
  int len = mclBnFr_getStr (buf, MAX_LENGTH_SERIALIZATION, x, 16);
  if (len == 0)
    return NULL;
  s = (char *) malloc (len + 1);
  strncpy (s, buf, len);
  s[len] = '\0';
  return s;
}

int
Zp_fromHexString (Zp * x, const char *s)
{

//Zp_deserialize(x,s,strlen(s));
  return mclBnFr_setStr (x, s, strlen (s), 16);
}

size_t
GT_toHexString (char *buf,const GT * e) // copy the string in hex and returns the length in *size (the length include the null terminating character)
{
//int len=G2_serialize(buf,MAX_LENGTH_SERIALIZATION,g);
  mclBn_setETHserialization (1);
  size_t len = mclBnGT_getStr (buf, MAX_LENGTH_SERIALIZATION, e,
			    MCLBN_IO_SERIALIZE_HEX_STR);
  if (len == 0)
    {
      mclBn_setETHserialization (0);
return 0;
    }
  //strncpy (s, buf, len);
  buf[len] = '\0';
  mclBn_setETHserialization (0);
  return len+1;
}

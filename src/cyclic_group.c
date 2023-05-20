// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlcs.h"
#include "err.h"
#include "pairing.h"
#include "cyclic_group.h"
#include "global_bufs.h"

#if CYC_GRP_BLS_G1 == 1
CycGrpG CycGrpGenerator;
static const char *g1Str =
  "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

int
group_init (void)
{
  int ret;
  Log_init ();
  ret = CycGrpG_setStr (&CycGrpGenerator, g1Str, strlen (g1Str), 16);
  if (ret != 0)
    {
      printf ("err ret=%d\n", ret);
      Log2 ("err in CycGrp_setStr:", ret);

      return 1;
    }
#if _SECRET_SHARING_ == 1
  InitTmpVar ();
  ComputeLagrangeCoeff ();
#endif

  return 0;
}

void
generate_public_key (CycGrpG * PK, const CycGrpZp * sk)
{
  CycGrpG_mul (PK, &CycGrpGenerator, sk);

}

void
generate_secret_key (CycGrpZp * sk)
{
  ASSERT (!CycGrpZp_setRand (sk));
}
#else // else we use either openssl EC or RSA
CycGrpG *CycGrpGenerator;
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
BN_CTX *bn_ctx;
EC_GROUP *ec_group = NULL;
int Order_bits;
#if CYC_GRP_RSA ==1
BIGNUM *RSA_modulus;
BIGNUM *RSA_pk;
int
group_init (const char *modulus, const char *pk)
{
  Log_init ();
  bn_ctx = BN_CTX_new ();
  RSA_modulus = BN_new ();
  RSA_pk = BN_new ();
  if (BN_hex2bn (&RSA_modulus, modulus) == 0 || BN_hex2bn (&RSA_pk, pk) == 0)
    {
      printf ("err in initializing the RSA modulus and public key\n");
      Log ("err in initializing the RSA modulus and public key");
      return 1;
    }

  Order_bits = BN_num_bits (RSA_pk);
  if (SERIALIZATION_CYCGRPZP_RATIO < ((Order_bits - 1) / 256 + 1) * 3)
    {
      printf
	("Panic: this curve requires that you changed the definition of the string SERIALIZATION_CYCGRPZP_RATIO in the file include/global_bufs.h to %d and recompile\n",
	 ((Order_bits - 1) / 256 + 1) * 2 + 1);
      Log2
	("Panic: this curve requires that you changed the definition of the string SERIALIZATION_CYCGRPZP_RATIO in the file include/global_bufs.h to %d and recompile",
	 ((Order_bits - 1) / 256 + 1) * 2 + 1);
      exit (1);
    }
  return 0;
}
#else
int bjj_flag = 0;		// we set to 1 if we use babyjubjub
CycGrpZp Order;
int
group_init (int curve_type)
{
  Log_init ();
  if (curve_type == 0)
    {
#if _SECRET_SHARING_ == 1
      printf
	("babyjubjub support not available in the secret sharing variant. Aborting\n");
      Log
	("babyjubjub support not available in the secret sharing variant. Aborting\n");
      exit (1);
#endif
      ec_group = babyjubjub_init ();
    }
  else
    ec_group = EC_GROUP_new_by_curve_name (curve_type);
  if (ec_group == NULL)
    {
      printf ("err in initializing the group\n");
      Log ("err in initializing the group");
      return 1;
    }
  CycGrpGenerator = (CycGrpG *) malloc (sizeof (CycGrpG));
  CycGrpGenerator->P = EC_POINT_new (ec_group);

  EC_POINT_copy (CycGrpGenerator->P, EC_GROUP_get0_generator (ec_group));
  bn_ctx = BN_CTX_new ();

  Order.B = BN_new ();
  if (!EC_GROUP_get_order (ec_group, Order.B, NULL))
    return 1;
  Order_bits = BN_num_bits (Order.B);
  if (SERIALIZATION_CYCGRPZP_RATIO < ((Order_bits - 1) / 256 + 1) * 3)
    {
      printf
	("Panic: this curve requires that you changed the definition of the string SERIALIZATION_CYCGRPZP_RATIO in the file include/global_bufs.h to %d and recompile\n",
	 ((Order_bits - 1) / 256 + 1) * 2 + 1);
      Log2
	("Panic: this curve requires that you changed the definition of the string SERIALIZATION_CYCGRPZP_RATIO in the file include/global_bufs.h to %d and recompile",
	 ((Order_bits - 1) / 256 + 1) * 2 + 1);
      exit (1);
    }
#if _SECRET_SHARING_ == 1
  InitTmpVar ();
  ComputeLagrangeCoeff ();
#endif
  return 0;
}
#endif

void
generate_public_key (CycGrpG * PK, const CycGrpZp * sk)
{
  CycGrpG_new (PK);
  CycGrpG_mul (PK, CycGrpGenerator, sk);
}

void
generate_secret_key (CycGrpZp * sk)
{
  CycGrpZp_new (sk);
  ASSERT (!CycGrpZp_setRand (sk));
}

#endif

void
CycGrpZp_copy (CycGrpZp * a, const CycGrpZp * b)
{
  CycGrpZp_serialize (buf_for_serializing, sizeof (buf_for_serializing), b);
  CycGrpZp_deserialize (a, buf_for_serializing, sizeof (buf_for_serializing));
}

void
CycGrpG_copy (CycGrpG * a, const CycGrpG * b)
{

  CycGrpG_serialize (buf_for_serializing, sizeof (buf_for_serializing), b);
  CycGrpG_deserialize (a, buf_for_serializing, sizeof (buf_for_serializing));
}

char *
CycGrpZp_toHexString (const CycGrpZp * a)
{
  char *s;
#if CYC_GRP_BLS_G1 == 1
  char buf[MAX_LENGTH_SERIALIZATION];
  size_t len;
  len = mclBnFr_getStr (buf, MAX_LENGTH_SERIALIZATION, a, 16);
  s = (char *) malloc (len + 1);
  strncpy (s, buf, len);
  s[len] = '\0';
#else
  s = BN_bn2hex (a->B);
#endif
  return s;
}

int
CycGrpZp_fromHexString (CycGrpZp * x, const char *s)
{
//CycGrpZp_deserialize(x,(unsigned char *)s,strlen(s));
#if CYC_GRP_BLS_G1 == 1
  return mclBnFr_setStr (x, s, strlen (s), 16);

#else
  return CycGrpZp_deserialize (x, (unsigned char *) s, strlen (s));
#endif
}

char *
CycGrpG_toHexString (const CycGrpG * a)
{
  char *s;
#if CYC_GRP_BLS_G1 == 1
  char buf[MAX_LENGTH_SERIALIZATION];
  size_t len;
  len = mclBnG1_getStr (buf, MAX_LENGTH_SERIALIZATION, a, 16);
  s = (char *) malloc (len + 1);
  strncpy (s, buf, len);
  s[len] = '\0';
#else
#if CYC_GRP_RSA == 1
  s = BN_bn2hex (a->P);
#else
  s = EC_POINT_point2hex (ec_group, a->P, POINT_CONVERSION_COMPRESSED, NULL);
#endif
#endif
  return s;
}

char *
CycGrpG_toHexStringUncompressed (const CycGrpG * a)
{
  char *s;
#if CYC_GRP_BLS_G1 == 1
  char buf[MAX_LENGTH_SERIALIZATION];
  size_t len;
  len = mclBnG1_getStr (buf, MAX_LENGTH_SERIALIZATION, a, 16);
  s = (char *) malloc (len + 1);
  strncpy (s, buf, len);
  s[len] = '\0';
#else
#if CYC_GRP_RSA == 1
  s = BN_bn2hex (a->P);
#else
  s =
    EC_POINT_point2hex (ec_group, a->P, POINT_CONVERSION_UNCOMPRESSED, NULL);
#endif
#endif
  return s;
}

int
CycGrpG_fromHexString (CycGrpG * g, const char *s)
{
//CycGrpG_deserialize(g,(unsigned char *)s,strlen(s));
#if CYC_GRP_BLS_G1 == 1
  return mclBnG1_setStr (g, s, strlen (s), 16);
#else
  return CycGrpG_deserialize (g, (unsigned char *) s, strlen (s));
#endif
}

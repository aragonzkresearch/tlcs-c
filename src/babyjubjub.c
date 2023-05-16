#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
EC_GROUP *
babyjubjub_init (void)
{
/* Curve BJJ https://eips.ethereum.org/EIPS/eip-2494 */
  BIGNUM *p, *a, *b, *A, *B, *u, *v, *x, *y, *tmp, *tmp2, *order, *cofactor;
  EC_GROUP *group, *BJJ;
  tmp = BN_new ();
  EC_POINT *P, *Q;
  BN_CTX *ctx;
  ctx = BN_CTX_new ();
  p = BN_new ();
  a = BN_new ();
  b = BN_new ();
  x = BN_new ();
  y = BN_new ();
  A = BN_new ();
  u = BN_new ();
  v = BN_new ();
  tmp = BN_new ();
  tmp = BN_new ();
  tmp2 = BN_new ();
  order = BN_new ();
  cofactor = BN_new ();
/*
p=21888242871839275222246405745257275088548364400416034343698204186575808495617
Equation in Montgomery form: By^2 = x^3 + A x^2 + x
Parameters: A = 168698, B = 1
The mapping between Montgomery M_{A,B} and Weierstrass E_{a,b} is given by the following equations:
a=(3-A^2)/3, b=(2A^3-9A)/27, (x,y)->(u,v)=(x+A/3,y)
Reference: https://en.wikipedia.org/wiki/Montgomery_curve
*/
  if (!BN_dec2bn
      (&p,
       "21888242871839275222246405745257275088548364400416034343698204186575808495617"))
    return NULL;
  if (!BN_dec2bn (&A, "168698"))
    return NULL;

  if (!BN_dec2bn (&tmp, "3"))
    return NULL;
  if (!BN_mod_sqr (tmp2, A, p, ctx))
    return NULL;		//tmp2=A^2
  if (!BN_mod_sub (tmp2, tmp, tmp2, p, ctx))
    return NULL;		//tmp2=3-A^2
  if (!BN_mod_inverse (tmp, tmp, p, ctx))
    return NULL;		//tmp=1/3
  if (!BN_mod_mul (a, tmp, tmp2, p, ctx))
    return NULL;		//a=(3-A^2)/3

  if (!BN_mod_sqr (tmp, A, p, ctx))
    return NULL;		//tmp=A^2
  if (!BN_mod_mul (tmp, tmp, A, p, ctx))
    return NULL;		//tmp=A^3
  if (!BN_dec2bn (&tmp2, "2"))
    return NULL;
  if (!BN_mod_mul (tmp, tmp2, tmp, p, ctx))
    return NULL;		//tmp=2*A^3
  if (!BN_dec2bn (&tmp2, "9"))
    return NULL;
  if (!BN_mod_mul (tmp2, tmp2, A, p, ctx))
    return NULL;		//tmp2=9*A
  if (!BN_mod_sub (tmp, tmp, tmp2, p, ctx))
    return NULL;		//tmp=2*A^3-9*A
  if (!BN_dec2bn (&tmp2, "27"))
    return NULL;
  if (!BN_mod_inverse (tmp2, tmp2, p, ctx))
    return NULL;		//tmp2=1/27
  if (!BN_mod_mul (b, tmp, tmp2, p, ctx))
    return NULL;		//b=(2*A^3-9*A)/27


  group = EC_GROUP_new (EC_GFp_mont_method ());
  if (!group)
    return NULL;
  if (!EC_GROUP_set_curve_GFp (group, p, a, b, ctx))
    return NULL;
  if (!BN_dec2bn
      (&x,
       "7117928050407583618111176421555214756675765419608405867398403713213306743542"))
    return NULL;		// base point u coordinate
//      if (!BN_dec2bn(&x, "7")) return NULL; generator u coordinate
  if (!BN_dec2bn (&tmp, "3"))
    return NULL;
  if (!BN_mod_inverse (tmp, tmp, p, ctx))
    return NULL;		//tmp=1/3
  if (!BN_mod_mul (tmp, tmp, A, p, ctx))
    return NULL;		//tmp=A/3
  if (!BN_mod_add (u, x, tmp, p, ctx))
    return NULL;		//u=x+A/3
  if (!BN_dec2bn
      (&v,
       "14577268218881899420966779687690205425227431577728659819975198491127179315626"))
    return NULL;		// base point v coordinate
//      if (!BN_dec2bn(&v, "4258727773875940690362607550498304598101071202821725296872974770776423442226")) return NULL; // generator v coordinate
  P = EC_POINT_new (group);
  if (!EC_POINT_set_affine_coordinates_GFp (group, P, u, v, ctx))
    return NULL;
  if (!EC_POINT_is_on_curve (group, P, ctx))
    return NULL;
  if (!BN_dec2bn
      (&order,
       "21888242871839275222246405745257275088614511777268538073601725287587578984328"))
    return NULL;
  if (!BN_dec2bn (&cofactor, "8"))
    return NULL;
  if (!EC_GROUP_set_generator (group, P, order, cofactor))
    return NULL;


  //if (!EC_GROUP_set_generator(group, P, u, v)) return NULL;
  /* 
     if (!EC_POINT_get_affine_coordinates_GFp(group, P, u, v, ctx)) return NULL;
     fprintf(stdout, "\nBJJ -- Generator:\n     u = 0x");
     BN_print_fp(stdout, u);
     fprintf(stdout, "\n     v = 0x");
     BN_print_fp(stdout, v);
     fprintf(stdout, "\n");
     fprintf(stdout, "verify degree ...");
     fprintf(stdout, "degree=%d\n",EC_GROUP_get_degree(group));
     EC_GROUP_get_order(group,tmp,ctx);
     fprintf(stdout, "order=%s\n",BN_bn2dec(tmp));
     Q=EC_POINT_new(group);
     if (!EC_GROUP_get_order(group, tmp, ctx)) return NULL;
     if (!EC_POINT_mul(group, Q, tmp, NULL, NULL, ctx)) return NULL;
     if (!EC_POINT_is_at_infinity(group, Q)) return NULL;
     //BN_dec2bn(&tmp,"2736030358979909402780800718157159386076813972158567259200215660948447373041"); // order of point
     //BN_dec2bn(&tmp,"21888242871839275222246405745257275088614511777268538073601725287587578984328"); // order of point
     BN_dec2bn(&tmp,"2736030358979909402780800718157159386076813972158567259200215660948447373041"); // order of point
     if (!EC_POINT_mul(group,Q,NULL,P,tmp,ctx))return NULL;
     fprintf(stdout, "\nis neutral %d:\n",EC_POINT_is_at_infinity(group,Q));
     fprintf(stdout, "\n");
   */

  return group;
}

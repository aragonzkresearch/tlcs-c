// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
// babyjubjub wrapper to openssl. Being  a wrapper it uses internally Weierstrass representation but we serialize to Twisted Edwards form (uncompressed)
// TODO: implement from scratch or use external library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
extern int bjj_flag;		// we set it to 1 in init here because we use babyjubjub
/*
The following sage script computes s=1, alpha
p=21888242871839275222246405745257275088548364400416034343698204186575808495617
R.<x> = PolynomialRing(Integers(p))
F=GF(p)
A=F(168698)
a=F(1)
b=F(1)
a=(3-A^2)/3 
b=(2*A^3-9*A)/27 
poly=x^3 +a*x+b
p=poly.roots()
alpha=F(7296080957279758407415468581752425029516121466805344781232734728858602888105)
s=F(1)
s=3*alpha^2+a
[s,alpha]


So the map from Weierstrass to Montgomery is (u,v)->(X,Y)=(u-alpha,v)
and the map from Montgomery Twisted Edwards is (X,Y)->(x,y)=(X/Y,(X-1)/(X+1))
Note: the sign is preserved.
*/
static const char *bjj_alpha =
  "7296080957279758407415468581752425029516121466805344781232734728858602888105";
static const char *bjj_p =
  "21888242871839275222246405745257275088548364400416034343698204186575808495617";
static const char *bjj_A = "168698";	// coeff A of Montgomery form
extern BN_CTX *bn_ctx;
void
Weierstrass2TwistedEdwards (char *E, const char *W)
{
  BIGNUM *u = BN_new ();
  BIGNUM *v = BN_new ();
  BIGNUM *X = BN_new ();
  BIGNUM *Y = BN_new ();
  BIGNUM *x = BN_new ();
  BIGNUM *y = BN_new ();
  BIGNUM *alpha = BN_new ();
  BIGNUM *p = BN_new ();
  BIGNUM *tmp = BN_new ();
  BIGNUM *tmp2 = BN_new ();
  char Wu[65];
  char Wv[65];
  strncpy (Wu, W + 2, 64);
  Wu[64] = '\0';
  strncpy (Wv, W + 2 + 64, 64);
  Wv[64] = '\0';
//printf("P in Weierstrass: %s\n",W);
  BN_hex2bn (&u, Wu);
  BN_hex2bn (&v, Wv);
  BN_dec2bn (&alpha, bjj_alpha);
  BN_dec2bn (&p, bjj_p);
  BN_copy (Y, v);
  BN_mod_sub (X, u, alpha, p, bn_ctx);	// (X,Y) are now in Montgomery form
// now going from Montgomery to Twisted Edwards 
  BN_mod_inverse (tmp, Y, p, bn_ctx);	// tmp=1/Y
  BN_mod_mul (x, X, tmp, p, bn_ctx);	// x=X*tmp=X/Y
  BN_dec2bn (&tmp, "1");
  BN_dec2bn (&tmp2, "1");
  BN_mod_add (tmp, X, tmp, p, bn_ctx);	// tmp=X+1
  BN_mod_inverse (tmp, tmp, p, bn_ctx);	// tmp=1/tmp=1/(X+1)
  BN_mod_sub (tmp2, X, tmp2, p, bn_ctx);	// tmp2=X-1
  BN_mod_mul (y, tmp2, tmp, p, bn_ctx);	// y=tmp2*tmp=(X-1)/(X+1)
  /*
     printf("Weierstrass form u: %s\n",BN_bn2dec(u));
     printf("Weierstrass form v: %s\n",BN_bn2dec(v));
     printf("Montgomery form X: %s\n",BN_bn2dec(X));
     printf("Montgomery form Y: %s\n",BN_bn2dec(Y));
     printf("Edwards form x: %s\n",BN_bn2dec(x));
     printf("Edwards form y: %s\n",BN_bn2dec(y));
   */
  memset (E, '0', 130);
  E[0] = '0';
  E[1] = '4';
  char *x_hex = BN_bn2hex (x);
  char *y_hex = BN_bn2hex (y);
  size_t x_len = strlen (x_hex);
  size_t y_len = strlen (y_hex);
  strncpy (E + 2 + (64 - x_len), x_hex, x_len);
  strncpy (E + 66 + (64 - y_len), y_hex, y_len);
  E[130] = '\0';
//printf("x: %s y:%s strlenx: %d strleny: %d E:%s\n",BN_bn2hex(x),BN_bn2hex(y),strlen(BN_bn2hex(x)),strlen(BN_bn2hex(y)),E);
}


/* The map from Weierstrass to Montgomery is (x,y)->(X,Y)=((1+y)/(1-y),(1+y)/(x(1-y)))
and the map from Montgomery to Weierstrass is (X,Y)->(u,v)=(X+A/3,Y)
*/

int
TwistedEdwards2Weierstrass (char *W, const char *E)
{
  BIGNUM *u = BN_new ();
  BIGNUM *v = BN_new ();
  BIGNUM *X = BN_new ();
  BIGNUM *Y = BN_new ();
  BIGNUM *x = BN_new ();
  BIGNUM *y = BN_new ();
  BIGNUM *alpha = BN_new ();
  BIGNUM *p = BN_new ();
  BIGNUM *tmp = BN_new ();
  BIGNUM *tmp2 = BN_new ();
  BIGNUM *tmp3 = BN_new ();
  BIGNUM *A = BN_new ();
  char Ex[65];
  char Ey[65];
  strncpy (Ex, E + 2, 64);
  Ex[64] = '\0';
  strncpy (Ey, E + 2 + 64, 64);
  Ey[64] = '\0';
//printf("P in Edwards: %s\n",E);
  if (!BN_hex2bn (&x, Ex))
    return 1;
  if (!BN_hex2bn (&y, Ey))
    return 1;
  if (!BN_dec2bn (&alpha, bjj_alpha))
    return 1;
  if (!BN_dec2bn (&p, bjj_p))
    return 1;
  if (!BN_dec2bn (&tmp, "1"))
    return 1;
  if (!BN_dec2bn (&tmp2, "1"))
    return 1;
  if (!BN_mod_add (tmp, tmp, y, p, bn_ctx))
    return 1;			// tmp= 1+y
  if (!BN_mod_sub (tmp2, tmp2, y, p, bn_ctx))
    return 1;			// tmp2= 1-y
  if (!BN_mod_inverse (tmp2, tmp2, p, bn_ctx))
    return 1;			// tmp2=1/(1-y)
  if (!BN_mod_mul (X, tmp, tmp2, p, bn_ctx))
    return 1;			// X=tmp*tmp2=(1+y)/(1-y)
  if (!BN_mod_inverse (tmp3, x, p, bn_ctx))
    return 1;			// tmp3=1/x
  if (!BN_mod_mul (tmp2, tmp2, tmp3, p, bn_ctx))
    return 1;			// tmp2=tmp2*tmp3=1/(x(1-y))
  if (!BN_mod_mul (Y, tmp, tmp2, p, bn_ctx))
    return 1;			// Y=tmp*tmp2=(1+y)/(x(1-y)) 
// Now (X,Y) is in Montgomery form
// Now we go from Montgomery to Weierstrass 
  if (!BN_dec2bn (&tmp, "3"))
    return 1;
  if (!BN_dec2bn (&A, bjj_A))
    return 1;
  if (!BN_mod_inverse (tmp, tmp, p, bn_ctx))
    return 1;			// tmp=1/3
  if (!BN_mod_mul (tmp, tmp, A, p, bn_ctx))
    return 1;			// tmp=A/3
  if (!BN_mod_add (u, X, tmp, p, bn_ctx))
    return 1;			// u=X+tmp=X+A/3
  if (!BN_copy (v, Y))
    return 1;

/*
printf("Edwards form x: %s\n",BN_bn2dec(x));
printf("Edwards form y: %s\n",BN_bn2dec(y));
printf("Montgomery form X: %s\n",BN_bn2dec(X));
printf("Montgomery form Y: %s\n",BN_bn2dec(Y));
printf("Weierstrass form u: %s\n",BN_bn2dec(u));
printf("Weierstrass form v: %s\n",BN_bn2dec(v));
*/
  memset (W, '0', 130);
  W[0] = '0';
  W[1] = '4';
  char *u_hex = BN_bn2hex (u);
  char *v_hex = BN_bn2hex (v);
  size_t u_len = strlen (u_hex);
  size_t v_len = strlen (v_hex);
  strncpy (W + 2 + (64 - u_len), u_hex, u_len);
  strncpy (W + 66 + (64 - v_len), v_hex, v_len);
  W[130] = '\0';
  return 0;
}

EC_GROUP *
babyjubjub_init (void)
{
/* Curve BJJ https://eips.ethereum.org/EIPS/eip-2494 */
  BIGNUM *p, *a, *b, *A, *u, *v, *x, *tmp, *tmp2, *order, *cofactor;
  EC_GROUP *group;
  tmp = BN_new ();
  EC_POINT *P;
  p = BN_new ();
  a = BN_new ();
  b = BN_new ();
  x = BN_new ();
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
  bn_ctx = BN_CTX_new ();
  if (!BN_dec2bn (&p, bjj_p))
    return NULL;
  if (!BN_dec2bn (&A, bjj_A))
    return NULL;

  if (!BN_dec2bn (&tmp, "3"))
    return NULL;
  if (!BN_mod_sqr (tmp2, A, p, bn_ctx))
    return NULL;		//tmp2=A^2
  if (!BN_mod_sub (tmp2, tmp, tmp2, p, bn_ctx))
    return NULL;		//tmp2=3-A^2
  if (!BN_mod_inverse (tmp, tmp, p, bn_ctx))
    return NULL;		//tmp=1/3
  if (!BN_mod_mul (a, tmp, tmp2, p, bn_ctx))
    return NULL;		//a=(3-A^2)/3

  if (!BN_mod_sqr (tmp, A, p, bn_ctx))
    return NULL;		//tmp=A^2
  if (!BN_mod_mul (tmp, tmp, A, p, bn_ctx))
    return NULL;		//tmp=A^3
  if (!BN_dec2bn (&tmp2, "2"))
    return NULL;
  if (!BN_mod_mul (tmp, tmp2, tmp, p, bn_ctx))
    return NULL;		//tmp=2*A^3
  if (!BN_dec2bn (&tmp2, "9"))
    return NULL;
  if (!BN_mod_mul (tmp2, tmp2, A, p, bn_ctx))
    return NULL;		//tmp2=9*A
  if (!BN_mod_sub (tmp, tmp, tmp2, p, bn_ctx))
    return NULL;		//tmp=2*A^3-9*A
  if (!BN_dec2bn (&tmp2, "27"))
    return NULL;
  if (!BN_mod_inverse (tmp2, tmp2, p, bn_ctx))
    return NULL;		//tmp2=1/27
  if (!BN_mod_mul (b, tmp, tmp2, p, bn_ctx))
    return NULL;		//b=(2*A^3-9*A)/27


  group = EC_GROUP_new (EC_GFp_mont_method ());
  if (!group)
    return NULL;
  if (!EC_GROUP_set_curve_GFp (group, p, a, b, bn_ctx))
    return NULL;
  if (!BN_dec2bn
      (&x,
       "7117928050407583618111176421555214756675765419608405867398403713213306743542"))
    return NULL;		// base point u coordinate
//      if (!BN_dec2bn(&x, "7")) return NULL; generator u coordinate
  if (!BN_dec2bn (&tmp, "3"))
    return NULL;
  if (!BN_mod_inverse (tmp, tmp, p, bn_ctx))
    return NULL;		//tmp=1/3
  if (!BN_mod_mul (tmp, tmp, A, p, bn_ctx))
    return NULL;		//tmp=A/3
  if (!BN_mod_add (u, x, tmp, p, bn_ctx))
    return NULL;		//u=x+A/3
  if (!BN_dec2bn
      (&v,
       "14577268218881899420966779687690205425227431577728659819975198491127179315626"))
    return NULL;		// base point v coordinate
//      if (!BN_dec2bn(&v, "4258727773875940690362607550498304598101071202821725296872974770776423442226")) return NULL; // generator v coordinate
  P = EC_POINT_new (group);
  if (!EC_POINT_set_affine_coordinates_GFp (group, P, u, v, bn_ctx))
    return NULL;
  if (!EC_POINT_is_on_curve (group, P, bn_ctx))
    return NULL;
  if (!BN_dec2bn
      (&order,
       "21888242871839275222246405745257275088614511777268538073601725287587578984328"))
    return NULL;
  if (!BN_dec2bn (&cofactor, "8"))
    return NULL;
  if (!EC_GROUP_set_generator (group, P, order, cofactor))
    return NULL;
  bjj_flag = 1;
  return group;
}

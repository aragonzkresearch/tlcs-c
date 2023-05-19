// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <mcl/bn_c384_256.h>
#include "tlcs.h"
#include "pairing.h"
#include "cyclic_group.h"
#include "err.h"


char *
SerializePartyOutput (const CycGrpG * PK, const Proof * pi, size_t * size)
{
  char *s = (char *) malloc (1000000);
  char *tmps;
  int i, j;
  size_t len = 0, tmplen;
// serialize PK
#if CYC_GRP_RSA == 1 || CYC_GRP_BLS_G1 == 1
  tmps = CycGrpG_toHexString (PK);
#else
  if (bjj_flag)
    {
      tmps = (char *) malloc (131);	// 131 is the length of a serialized bjj point
      Weierstrass2TwistedEdwards (tmps, CycGrpG_toHexStringUncompressed (PK));
    }
  else
    tmps = CycGrpG_toHexString (PK);
#endif
//printf("PK: %s\n",tmps);
  tmplen = strlen (tmps);
  strcpy (s, tmps);
  len += tmplen + 1;
//free(tmps);


  for (i = 0; i < NUM_REPETITIONS; i++)	//serialize CommitmentTuples
    for (j = 0; j < NUM_COLUMNS; j++)
      {
	tmps = G2_toHexString (&pi->C[i][j].T);	// serialize C[i][j].T
//printf("T[%d]: %s\n",j,tmps);
	tmplen = strlen (tmps);
	strcpy (s + len, tmps);
	len += tmplen + 1;
//free(tmps);
#if CYC_GRP_RSA == 1 || CYC_GRP_BLS_G1 == 1
	tmps = CycGrpG_toHexString (&pi->C[i][j].PK);	// serialize C[i][j].PK
#else
	if (bjj_flag)
	  {
	    tmps = (char *) malloc (131);
	    memset (tmps, 0, 131);
	    Weierstrass2TwistedEdwards (tmps,
					CycGrpG_toHexStringUncompressed
					(&pi->C[i][j].PK));
	  }
	else
	  tmps = CycGrpG_toHexString (&pi->C[i][j].PK);	// serialize C[i][j].PK
#endif
//printf("PK[%d]: %s\n",j,tmps);
	tmplen = strlen (tmps);
//if (tmplen<80) printf("tmps: %s,uncompressed PK[%d][%d]: %s compressed: %s\n",tmps,i,j,CycGrpG_toHexStringUncompressed(&pi->C[i][j].PK),CycGrpG_toHexString(&pi->C[i][j].PK));
	strcpy (s + len, tmps);
	len += tmplen + 1;
//free(tmps);

	memcpy (s + len, (char *) pi->C[i][j].y, SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO);	// serialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",*((unsigned char *)s+len+k));
printf("\n");
}*/
	len += SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO;

      }

  for (i = 0; i < NUM_REPETITIONS; i++)
    {				//serialize OpeningTuples
/*
tmps=CycGrpZp_toHexString(&pi->O[i].sk); // serialize O[i].sk
printf("opened sk: %s\n",tmps);
tmplen=strlen(tmps);
strcpy(s+len,tmps);
len+=tmplen+1;
//free(tmps);
*/
      tmps = Zp_toHexString (&pi->O[i].t);	// serialize O[i].t
//printf("t[%d]: %s\n",i,tmps);
      tmplen = strlen (tmps);
      strcpy (s + len, tmps);
      len += tmplen + 1;
//free(tmps);

    }
//printf("length string: %d\n",(int) len);
//write(2,s,len);
  if (size != NULL)
    *size = len;
  return s;
}



int
DeserializePartyOutput (CycGrpG * PK, Proof * pi, const char *buf, size_t * size)	// TODO: we assume that the string buf is sufficiently long to prevent buffer overflows. Precisely, buf should be as long as the length of a proof for the given configuration you choose
{
  int i, j;
  char *s = (char *) buf;
// deserialize PK
#if CYC_GRP_BLS_G1 == 1
#else
  CycGrpG_new (PK);
#endif
#if CYC_GRP_RSA == 1 || CYC_GRP_BLS_G1 == 1
  if (CycGrpG_fromHexString (PK, s) == -1)
    {
      Log ("Error in deserializing the proof");
      return -1;
    }
#else
  if (bjj_flag)
    {
      char W[131];
      int ret;
      ret = TwistedEdwards2Weierstrass (W, s);
      char E[131];
      Weierstrass2TwistedEdwards (E, W);
      if (ret == 1 || CycGrpG_fromHexString (PK, W) == -1)
	{
//printf("dsldslkfl ret:%d s:%s W:%s E:%s\n",ret,s,W,E);
	  Log ("Error in deserializing the proof");
	  return -1;
	}
    }
  else if (CycGrpG_fromHexString (PK, s) == -1)
    {
      Log ("Error in deserializing the proof");
      return -1;
    }
#endif
//printf("deserialized PK: %s\n",CycGrpG_toHexString(PK));
  s += strlen (s) + 1;

  for (i = 0; i < NUM_REPETITIONS; i++)	//deserialize CommitmentTuples
    for (j = 0; j < NUM_COLUMNS; j++)
      {
	if (G2_fromHexString (&pi->C[i][j].T, s) == -1)
	  {			// deserialize C[i][j].T
	    Log ("Error in deserializing the proof");
	    return -1;
	  }

//printf("deserialized T[%d]: %s\n",j,G2_toHexString(&pi->C[i][j].T));
	s += strlen (s) + 1;

#if CYC_GRP_BLS_G1 == 1
#else
	CycGrpG_new (&pi->C[i][j].PK);
#endif
#if CYC_GRP_RSA == 1 || CYC_GRP_BLS_G1 == 1
	if (CycGrpG_fromHexString (&pi->C[i][j].PK, s) == -1)
	  {			// deserialize C[i][j].PK
	    Log ("Error in deserializing the proof");
	    return -1;
	  }
#else
	if (bjj_flag)
	  {
	    char W[131];
	    int ret;
	    ret = TwistedEdwards2Weierstrass (W, s);
	    char E[131];
	    Weierstrass2TwistedEdwards (E, W);
	    if (ret == 1 || CycGrpG_fromHexString (&pi->C[i][j].PK, W) == -1)
	      {
//printf("dsldslkfl i:%d j:%d ret:%d s:%s W:%s E:%s\n",i,j,ret,s,W,E);
		Log ("Error in deserializing the proof");
		return -1;
	      }
	  }
	else if (CycGrpG_fromHexString (&pi->C[i][j].PK, s) == -1)
	  {			// deserialize C[i][j].PK
	    Log ("Error in deserializing the proof");
	    return -1;
	  }
#endif
//printf("deserialized PK[%d]: %s\n",j,CycGrpG_toHexString(&pi->C[i][j].PK));
	s += strlen (s) + 1;

//pi->C[i][j].y=(unsigned char *)malloc(SHA256_DIGEST_LENGTH*SERIALIZATION_CYCGRPZP_RATIO);
	memcpy ((char *) pi->C[i][j].y, s, SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO);	// deserialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",(unsigned char)pi->C[i][j].y[k]);
//printf("\n");
}*/
	s += SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO;
      }

  for (i = 0; i < NUM_REPETITIONS; i++)
    {				// deserialize OpeningTuples
/*
#if CYC_GRP_BLS_G1 == 1
#else
CycGrpZp_new(&pi->O[i].sk);
#endif
CycGrpZp_fromHexString(&pi->O[i].sk,s); // deserialize O[i].sk
printf("deserialized opened sk: %s\n",CycGrpZp_toHexString(&pi->O[i].sk));
s+=strlen(s)+1;
*/
      if (Zp_fromHexString (&pi->O[i].t, s) == -1)
	{			// deserialize O[i].t
	  Log ("Error in deserializing the proof");
	  return -1;
	}
//printf("opened t[%d]: %s\n",i,Zp_toHexString(&pi->O[i].t));
      s += strlen (s) + 1;

    }
  if (size != NULL)
    *size = s - buf;
  return 0;
}















char *
SerializePKandCommitment (const CycGrpG * PK,
			  const CommitmentTuple C[][NUM_COLUMNS])
{
  char *s = (char *) malloc (1000000);
  char *tmps;
  int i, j;
  size_t len = 0, tmplen;
// serialize PK
  tmps = CycGrpG_toHexString (PK);
//printf("PK: %s\n",tmps);
  tmplen = strlen (tmps);
  strcpy (s, tmps);
  len += tmplen + 1;
//free(tmps);


  for (i = 0; i < NUM_REPETITIONS; i++)	//serialize CommitmentTuples
    for (j = 0; j < NUM_COLUMNS; j++)
      {
	tmps = G2_toHexString (&C[i][j].T);	// serialize C[i][j].T
//printf("T[%d]: %s\n",j,tmps);
	tmplen = strlen (tmps);
	strcpy (s + len, tmps);
	len += tmplen + 1;
//free(tmps);

	tmps = CycGrpG_toHexString (&C[i][j].PK);	// serialize C[i][j].PK
//printf("PK[%d]: %s\n",j,tmps);
	tmplen = strlen (tmps);
	strcpy (s + len, tmps);
	len += tmplen + 1;
//free(tmps);

	memcpy (s + len, (char *) C[i][j].y, SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO);	// serialize C[i][j].y
//printf("y[%d]:",j);
/*{
int k; for (k=0;k<32;k++) printf("%x ",*((unsigned char *)s+len+k));
printf("\n");
}*/
	len += SHA256_DIGEST_LENGTH * SERIALIZATION_CYCGRPZP_RATIO;

      }

//printf("length string: %d\n",(int) len);
//write(2,s,len);
  return s;
}

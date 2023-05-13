// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
int g_err = 0;

FILE *LOG_FP;

void
Log_init (void)
{
  LOG_FP = fopen (".log_tlcs", "a");

  if (!LOG_FP)
    {
      printf ("error in opening the log file .log_tlcs\n");
      exit (1);
    }
}

void
Log (char *msg)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;
  fprintf (LOG_FP, "%s: %s\n", ctime (&current), msg);


}

void
Log2 (char *msg, int i)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;
  fprintf (LOG_FP, "%s: %s %d\n", ctime (&current), msg, i);


}

void
Log3 (int i, double t)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;

  fprintf (LOG_FP,
	   "%s: time spent by party %d in computing his public key and proof: %fs\n",
	   ctime (&current), i, t);

}

void
Log3b (double t)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;

  fprintf (LOG_FP,
	   "%s: time spent by the party in computing his public key and proof: %fs\n",
	   ctime (&current), t);

}

void
Log4 (int i, double t)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;

  fprintf (LOG_FP,
	   "%s: time spent by verifier on verifying proof of party %d: %fs\n",
	   ctime (&current), i, t);

}

void
Log5 (int i, double t)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;

  fprintf (LOG_FP, "%s: time spent in inversion for %d parties: %fs\n",
	   ctime (&current), i, t);

}

void
Log6 (uint64_t round)
{
  time_t current;
  current = time (NULL);

  if (!LOG_FP)
    return;

  fprintf (LOG_FP,
	   "%s: general secret key for round %lu successfully inverted\n",
	   ctime (&current), round);

}

void
Err (void)
{
  time_t current;
  current = time (NULL);
  if (g_err)
    {
      fprintf (LOG_FP, "%s: err %d\n", ctime (&current), g_err);
      exit (1);
    }
  else
    {
      fprintf (LOG_FP, "%s: no err\n", ctime (&current));
      return;
    }
}

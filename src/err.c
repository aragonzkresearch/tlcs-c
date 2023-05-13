// The TLCS system was initially described here:
// https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ
// 
// Vincenzo Iovino, 2023, Aragon ZK Research
#include <stdio.h>
#include <stdlib.h>
int g_err = 0;

void
Err (void)
{
  if (g_err)
    {
      printf ("err %d\n", g_err);
      exit (1);
    }
  else
    {
      printf ("no err\n");
      return;
    }
}

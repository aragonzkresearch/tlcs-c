#!/bin/bash
  echo -ne "714\n" > tmp
  echo -n $1 >> tmp
  echo -ne "\n" >> tmp
  cat > tmpproof
  ./bin/verifier4blockchain tmpproof tmpverified < tmp
  cat tmpverified
  rm -f tmpproof
  rm -f tmp
  rm -f tmpverified

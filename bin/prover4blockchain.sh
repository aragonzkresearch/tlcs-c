#!/bin/bash
  echo -ne "714\n" >tmp
  echo -ne $1 >>tmp
  echo -ne "\n" >> tmp
  rm -f tmpproof
  ./bin/prover4blockchain tmpproof < tmp
  cat tmpproof 

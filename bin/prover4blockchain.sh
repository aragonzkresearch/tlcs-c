#!/bin/bash
  echo -ne "714\n" >tmp
  echo -ne $1 >>tmp
  echo -ne "\n" >> tmp
  ./bin/prover4blockchain tmpproof < tmp
  cat tmpproof 
  rm -f tmpproof
  rm -f tmp

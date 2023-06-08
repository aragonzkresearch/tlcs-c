#!/bin/bash
# arguments: round signature pk [list of 0/1 values]
  echo -ne "714\n" >tmp
  echo -n $1 >> tmp
  echo -ne "\n" >> tmp
  echo -n $2 >> tmp
  echo -ne "\n" >> tmp
  echo -n $3 > tmpaggregatedpk
  echo -ne "\n" >> tmpaggregatedpk
  cat > tmpproof
  shift
  shift
  shift
  ./bin/invert4blockchain tmpproof tmpaggregatedpk $@ < tmp
  rm -f tmpproof
  rm -f tmpaggregatedpk
  rm -f tmp


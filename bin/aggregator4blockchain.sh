#!/bin/bash
  echo -ne "714\n" >tmp
cat > tmpproof
  ./bin/demo_aggregator tmpproof tmpaggregatedpk $@ < tmp
  cat tmpaggregatedpk
  rm -f tmpproof
  rm -f tmpaggregatedpk
  rm -f tmp


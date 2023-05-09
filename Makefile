CC=g++
CCOPT=-Wall -fopenmp -lpthread 
DFLAGS=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0
MCL_INCLUDE_PATH=mcl/include
IOPT=-I $(MCL_INCLUDE_PATH) -I ./include
LDFLAGS=-lcrypto mcl/lib/libmclbn384_256.a mcl/lib/libmcl.a 
all:  tlcs tests
tlcs: src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/tests/simulated_loe.c
	$(CC) -o  bin/tlcs src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/tests/simulated_loe.c $(IOPT)  $(LDFLAGS) $(DFLAGS) $(CCOPT)
tests: examples/tests.c 
	$(CC) -o  bin/tests examples/tests.c src/err.c $(IOPT)  $(LDFLAGS) $(DFLAGS) $(CCOPT)
clean:
	rm -f bin/tlcs bin/tests *.o src/*.o examples/*.o

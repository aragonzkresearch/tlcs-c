CC=g++
CCOPT=-Wall -fopenmp -lpthread 
DFLAGS0=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0
DFLAGS1=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=1
DFLAGS2=-DPARALLELISM=0 -D_DEBUG_=0 -DCYC_GRP_BLS_G1=0
MCL_INCLUDE_PATH=mcl/include
IOPT=-I $(MCL_INCLUDE_PATH) -I ./include
LDFLAGS=-lcrypto mcl/lib/libmclbn384_256.a mcl/lib/libmcl.a 
all:  tlcs_bls_g1 tlcs tests demo_prover demo_aggregator demo_verifier demo_invert
tlcs: src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c src/global_bufs.c
	$(CC) -o  bin/tlcs src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
tlcs_bls_g1: src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c src/global_bufs.c
	$(CC) -o  bin/tlcs_bls_g1 src/cyclic_group.c src/err.c examples/tlcs.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS1) $(CCOPT)
demo_prover: src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c examples/demo_prover.c src/global_bufs.c
	$(CC) -o  bin/demo_prover src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c examples/demo_prover.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
demo_aggregator: src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c examples/demo_aggregator.c src/global_bufs.c
	$(CC) -o  bin/demo_aggregator src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c examples/demo_aggregator.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
demo_verifier: src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c examples/demo_verifier.c src/global_bufs.c
	$(CC) -o  bin/demo_verifier src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c examples/demo_verifier.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS2) $(CCOPT)
demo_invert: src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c examples/demo_invert.c src/global_bufs.c
	$(CC) -o  bin/demo_invert src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c examples/demo_invert.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS2) $(CCOPT)
tests: examples/tests.c src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/invert.c src/aggregate.c src/serialize.c src/tests/simulated_loe.c src/global_bufs.c
	$(CC) -o  bin/tests src/cyclic_group.c src/err.c src/pairing.c src/prover.c src/verifier.c src/aggregate.c src/invert.c src/serialize.c src/tests/simulated_loe.c examples/tests.c src/global_bufs.c $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
clean:
clean:
	rm -f bin/tlcs /bin/tlcs_bls_g1 bin/tests *.o src/*.o examples/*.o /bin/demo*

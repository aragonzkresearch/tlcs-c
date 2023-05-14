CC=g++
CCOPT=-Wall -fopenmp -lpthread -fPIC
DFLAGS0=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0
DFLAGS1=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=1 
DFLAGS2=-DPARALLELISM=0 -D_DEBUG_=0 -DCYC_GRP_BLS_G1=0
DFLAGS3=-DPARALLELISM=0 -D_DEBUG_=0 -DCYC_GRP_BLS_G1=1
DFLAGS3=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0 -DCYC_GRP_RSA=1
MCL_INCLUDE_PATH=mcl/include
IOPT=-I $(MCL_INCLUDE_PATH) -I ./include
LDFLAGS=-lcrypto mcl/lib/libmclbn384_256.a mcl/lib/libmcl.a 
all:  tlcs tlcs_bls_g1 tlcs_rsa tests demo_prover demo_aggregator demo_verifier demo_invert libtlcs libtlcs_bls_g1
cyclic_group.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/cyclic_group.c
cyclic_group_bls_g1.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/cyclic_group.c
cyclic_group_rsa.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/cyclic_group.c
pairing.o: src/pairing.c
	$(CC) -o src/pairing.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/pairing.c
pairing_bls_g1.o: src/pairing.c
	$(CC) -o src/pairing_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/pairing.c
pairing_rsa.o: src/pairing.c
	$(CC) -o src/pairing_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/pairing.c
err.o: src/err.c
	$(CC) -o src/err.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/err.c
err_bls_g1.o: src/err.c
	$(CC) -o src/err_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/err.c
err_rsa.o: src/err.c
	$(CC) -o src/err_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/err.c
prover.o: src/prover.c
	$(CC) -o src/prover.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/prover.c
prover_bls_g1.o: src/prover.c
	$(CC) -o src/prover_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/prover.c
prover_rsa.o: src/prover.c
	$(CC) -o src/prover_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/prover.c
verifier.o: src/verifier.c
	$(CC) -o src/verifier.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/verifier.c
verifier_bls_g1.o: src/verifier.c
	$(CC) -o src/verifier_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/verifier.c
verifier_rsa.o: src/verifier.c
	$(CC) -o src/verifier_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/verifier.c
invert.o: src/invert.c
	$(CC) -o src/invert.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/invert.c
invert_bls_g1.o: src/invert.c
	$(CC) -o src/invert_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/invert.c
invert_rsa.o: src/invert.c
	$(CC) -o src/invert_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/invert.c
aggregate.o: src/aggregate.c
	$(CC) -o src/aggregate.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/aggregate.c
aggregate_bls_g1.o: src/aggregate.c
	$(CC) -o src/aggregate_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/aggregate.c
aggregate_rsa.o: src/aggregate.c
	$(CC) -o src/aggregate_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/aggregate.c
serialize.o: src/serialize.c
	$(CC) -o src/serialize.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/serialize.c
serialize_bls_g1.o: src/serialize.c
	$(CC) -o src/serialize_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/serialize.c
serialize_rsa.o: src/serialize.c
	$(CC) -o src/serialize_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/serialize.c
global_bufs.o: src/global_bufs.c
	$(CC) -o src/global_bufs.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/global_bufs.c
global_bufs_bls_g1.o: src/global_bufs.c
	$(CC) -o src/global_bufs_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/global_bufs.c
global_bufs_rsa.o: src/global_bufs.c
	$(CC) -o src/global_bufs_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/global_bufs.c
simulated_loe.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/tests/simulated_loe.c
simulated_loe_bls_g1.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/tests/simulated_loe.c
simulated_loe_rsa.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/tests/simulated_loe.c
libtlcs: cyclic_group.o err.o pairing.o prover.o verifier.o invert.o aggregate.o serialize.o simulated_loe.o global_bufs.o serialize.o
	$(CC) -shared -o ./lib/libtlcs.so -fPIC src/prover.o -fPIC src/verifier.o -fPIC src/aggregate.c -fPIC src/invert.o -fPIC src/global_bufs.o -fPIC src/err.o -fPIC src/serialize.o -fPIC src/cyclic_group.o -fPIC src/pairing.o -fPIC src/tests/simulated_loe.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS0) 
libtlcs_bls_g1: cyclic_group_bls_g1.o err_bls_g1.o pairing_bls_g1.o prover_bls_g1.o verifier_bls_g1.o invert_bls_g1.o aggregate_bls_g1.o serialize_bls_g1.o simulated_loe_bls_g1.o global_bufs_bls_g1.o serialize_bls_g1.o
libtlcs_rsa: cyclic_group_rsa.o err_rsa.o pairing_rsa.o prover_rsa.o verifier_rsa.o invert_rsa.o aggregate_rsa.o serialize_rsa.o simulated_loe_rsa.o global_bufs_rsa.o serialize_rsa.o
	$(CC) -shared -o ./lib/libtlcs_rsa.so -fPIC src/prover_rsa.o -fPIC src/verifier_rsa.o -fPIC src/aggregate_rsa.o -fPIC src/invert_rsa.o -fPIC src/global_bufs_rsa.o -fPIC src/err_rsa.o -fPIC src/serialize_rsa.o -fPIC src/cyclic_group_rsa.o -fPIC src/pairing_rsa.o -fPIC src/tests/simulated_loe_rsa.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS3) 
	$(CC) -shared -o ./lib/libtlcs_bls_g1.so -fPIC src/prover_bls_g1.o -fPIC src/verifier_bls_g1.o -fPIC src/aggregate_bls_g1.o -fPIC src/invert_bls_g1.o -fPIC src/global_bufs_bls_g1.o -fPIC src/err_bls_g1.o -fPIC src/serialize_bls_g1.o -fPIC src/cyclic_group_bls_g1.o -fPIC src/pairing_bls_g1.o -fPIC src/tests/simulated_loe_bls_g1.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS1)
tlcs: libtlcs examples/tlcs.c 
	$(CC) -o  bin/tlcs examples/tlcs.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS0) $(CCOPT)
tlcs_bls_g1: libtlcs_bls_g1 examples/tlcs.c 
	$(CC) -o  bin/tlcs_bls_g1 examples/tlcs.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_bls_g1.so $(DFLAGS1) $(CCOPT)
tlcs_rsa: libtlcs_rsa examples/tlcs.c 
	$(CC) -o  bin/tlcs_rsa examples/tlcs.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_rsa.so $(DFLAGS3) $(CCOPT)
demo_prover: examples/demo_prover.c libtlcs
	$(CC) -o  bin/demo_prover examples/demo_prover.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS2) $(CCOPT)
demo_verifier: examples/demo_verifier.c libtlcs
	$(CC) -o  bin/demo_verifier examples/demo_verifier.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS2) $(CCOPT)
demo_aggregator: examples/demo_aggregator.c libtlcs
	$(CC) -o  bin/demo_aggregator examples/demo_aggregator.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS2) $(CCOPT)
demo_invert: examples/demo_invert.c libtlcs
	$(CC) -o  bin/demo_invert examples/demo_invert.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS2) $(CCOPT)
tests: examples/tests.c cyclic_group.o err.o pairing.o prover.o verifier.o invert.o aggregate.o serialize.o simulated_loe.o global_bufs.o
	$(CC) -o  bin/tests src/cyclic_group.o src/err.o src/pairing.o src/prover.o src/verifier.o src/aggregate.o src/invert.o src/serialize.o src/tests/simulated_loe.o examples/tests.c src/global_bufs.o $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
clean:
	rm -f bin/tlcs /bin/tlcs_bls_g1 bin/tests *.o src/*.o examples/*.o /bin/demo* src/*.o lib/*.so

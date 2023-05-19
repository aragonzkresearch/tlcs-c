CC=g++
CCOPT=-Wall -fopenmp -lpthread -fPIC -Wno-write-strings
DFLAGS0=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0
DFLAGS1=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=1 
DFLAGS2=-DPARALLELISM=0 -D_DEBUG_=0 -DCYC_GRP_BLS_G1=0
DFLAGS3=-DPARALLELISM=0 -D_DEBUG_=0 -DCYC_GRP_BLS_G1=1
DFLAGS3=-DPARALLELISM=0 -D_DEBUG_=1 -DCYC_GRP_BLS_G1=0 -DCYC_GRP_RSA=1
MCL_INCLUDE_PATH=mcl/include
IOPT=-I $(MCL_INCLUDE_PATH) -I ./include
LDFLAGS=-lcrypto mcl/lib/libmclbn384_256.a mcl/lib/libmcl.a 
all:  tlcs tlcs_bls_g1 tlcs_rsa tests demo_prover demo_aggregator demo_verifier demo_invert libtlcs libtlcs_bls_g1 tlcs_ss demo_prover_ss demo_verifier_ss demo_aggregator_ss demo_invert_ss
prover_ss.o: src/prover_ss.c
	$(CC) -o src/prover_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/prover_ss.c
babyjubjub.o: src/babyjubjub.c
	$(CC) -o src/babyjubjub.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/babyjubjub.c
babyjubjub_ss.o: src/babyjubjub.c
	$(CC) -o src/babyjubjub_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/babyjubjub.c
cyclic_group.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/cyclic_group.c
cyclic_group_ss.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/cyclic_group.c
cyclic_group_bls_g1.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/cyclic_group.c
cyclic_group_rsa.o: src/cyclic_group.c
	$(CC) -o src/cyclic_group_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/cyclic_group.c
pairing.o: src/pairing.c
	$(CC) -o src/pairing.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/pairing.c
pairing_ss.o: src/pairing.c
	$(CC) -o src/pairing_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/pairing.c
pairing_bls_g1.o: src/pairing.c
	$(CC) -o src/pairing_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/pairing.c
pairing_rsa.o: src/pairing.c
	$(CC) -o src/pairing_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/pairing.c
err.o: src/err.c
	$(CC) -o src/err.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/err.c
err_ss.o: src/err.c
	$(CC) -o src/err_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/err.c
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
verifier_ss.o: src/verifier_ss.c
	$(CC) -o src/verifier_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/verifier_ss.c
verifier_bls_g1.o: src/verifier.c
	$(CC) -o src/verifier_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/verifier.c
verifier_rsa.o: src/verifier.c
	$(CC) -o src/verifier_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/verifier.c
invert.o: src/invert.c
	$(CC) -o src/invert.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/invert.c
invert_ss.o: src/invert_ss.c
	$(CC) -o src/invert_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/invert_ss.c
invert_bls_g1.o: src/invert.c
	$(CC) -o src/invert_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/invert.c
invert_rsa.o: src/invert.c
	$(CC) -o src/invert_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/invert.c
aggregate.o: src/aggregate.c
	$(CC) -o src/aggregate.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/aggregate.c
aggregate_ss.o: src/aggregate.c
	$(CC) -o src/aggregate_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/aggregate.c
aggregate_bls_g1.o: src/aggregate.c
	$(CC) -o src/aggregate_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/aggregate.c
aggregate_rsa.o: src/aggregate.c
	$(CC) -o src/aggregate_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/aggregate.c
serialize.o: src/serialize.c
	$(CC) -o src/serialize.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/serialize.c
serialize_ss.o: src/serialize.c
	$(CC) -o src/serialize_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/serialize.c
serialize_bls_g1.o: src/serialize.c
	$(CC) -o src/serialize_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/serialize.c
serialize_rsa.o: src/serialize.c
	$(CC) -o src/serialize_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/serialize.c
global_bufs.o: src/global_bufs.c
	$(CC) -o src/global_bufs.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/global_bufs.c
global_bufs_ss.o: src/global_bufs.c
	$(CC) -o src/global_bufs_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/global_bufs.c
global_bufs_bls_g1.o: src/global_bufs.c
	$(CC) -o src/global_bufs_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/global_bufs.c
global_bufs_rsa.o: src/global_bufs.c
	$(CC) -o src/global_bufs_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/global_bufs.c
simulated_loe.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe.o $(CCOPT) $(IOPT) $(DFLAGS0) -c src/tests/simulated_loe.c
simulated_loe_ss.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe_ss.o $(CCOPT) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1 -c src/tests/simulated_loe.c
simulated_loe_bls_g1.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe_bls_g1.o $(CCOPT) $(IOPT) $(DFLAGS1) -c src/tests/simulated_loe.c
simulated_loe_rsa.o: src/tests/simulated_loe.c
	$(CC) -o src/tests/simulated_loe_rsa.o $(CCOPT) $(IOPT) $(DFLAGS3) -c src/tests/simulated_loe.c
libtlcs: cyclic_group.o err.o pairing.o prover.o verifier.o invert.o aggregate.o serialize.o simulated_loe.o global_bufs.o serialize.o babyjubjub.o 
	$(CC) -shared -o ./lib/libtlcs.so -fPIC src/prover.o -fPIC src/verifier.o -fPIC src/aggregate.o -fPIC src/invert.o -fPIC src/global_bufs.o -fPIC src/err.o -fPIC src/babyjubjub.o -fPIC src/serialize.o -fPIC src/cyclic_group.o -fPIC src/pairing.o -fPIC src/tests/simulated_loe.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS0) 
libtlcs_ss: cyclic_group_ss.o err_ss.o pairing_ss.o invert_ss.o aggregate_ss.o serialize_ss.o simulated_loe_ss.o global_bufs_ss.o babyjubjub_ss.o prover_ss.o verifier_ss.o
	$(CC) -shared -o ./lib/libtlcs_ss.so -fPIC src/aggregate_ss.o -fPIC src/prover_ss.o -fPIC src/verifier_ss.o -fPIC src/invert_ss.o -fPIC src/global_bufs_ss.o -fPIC src/err_ss.o -fPIC src/babyjubjub_ss.o -fPIC src/serialize_ss.o -fPIC src/cyclic_group_ss.o -fPIC src/pairing_ss.o -fPIC src/tests/simulated_loe_ss.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS0) -D_SECRET_SHARING_=1
libtlcs_bls_g1: cyclic_group_bls_g1.o err_bls_g1.o pairing_bls_g1.o prover_bls_g1.o verifier_bls_g1.o invert_bls_g1.o aggregate_bls_g1.o serialize_bls_g1.o simulated_loe_bls_g1.o global_bufs_bls_g1.o serialize_bls_g1.o
	$(CC) -shared -o ./lib/libtlcs_bls_g1.so -fPIC src/prover_bls_g1.o -fPIC src/verifier_bls_g1.o -fPIC src/aggregate_bls_g1.o -fPIC src/invert_bls_g1.o -fPIC src/global_bufs_bls_g1.o -fPIC src/err_bls_g1.o -fPIC src/serialize_bls_g1.o -fPIC src/cyclic_group_bls_g1.o -fPIC src/pairing_bls_g1.o -fPIC src/tests/simulated_loe_bls_g1.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS1)
libtlcs_rsa: cyclic_group_rsa.o err_rsa.o pairing_rsa.o prover_rsa.o verifier_rsa.o invert_rsa.o aggregate_rsa.o serialize_rsa.o simulated_loe_rsa.o global_bufs_rsa.o serialize_rsa.o
	$(CC) -shared -o ./lib/libtlcs_rsa.so -fPIC src/prover_rsa.o -fPIC src/verifier_rsa.o -fPIC src/aggregate_rsa.o -fPIC src/invert_rsa.o -fPIC src/global_bufs_rsa.o -fPIC src/err_rsa.o -fPIC src/serialize_rsa.o -fPIC src/cyclic_group_rsa.o -fPIC src/pairing_rsa.o -fPIC src/tests/simulated_loe_rsa.o $(CCOPT) $(LDFLAGS) $(IOPT) $(DFLAGS3) 
tlcs: libtlcs examples/tlcs.c 
	$(CC) -o  bin/tlcs examples/tlcs.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs.so $(DFLAGS0) $(CCOPT)
tlcs_ss: libtlcs_ss examples/tlcs_ss.c 
	$(CC) -o  bin/tlcs_ss examples/tlcs_ss.c $(IOPT) $(LDFLAGS) ./lib/libtlcs_ss.so $(DFLAGS0) -D_SECRET_SHARING_=1 $(CCOPT)
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
demo_prover_ss: examples/demo_prover.c libtlcs_ss
	$(CC) -o  bin/demo_prover_ss examples/demo_prover.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_ss.so $(DFLAGS2) -D_SECRET_SHARING_=1 $(CCOPT)
demo_verifier_ss: examples/demo_verifier.c libtlcs_ss
	$(CC) -o  bin/demo_verifier_ss examples/demo_verifier.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_ss.so $(DFLAGS2) -D_SECRET_SHARING_=1 $(CCOPT)
demo_aggregator_ss: examples/demo_aggregator.c libtlcs_ss
	$(CC) -o  bin/demo_aggregator_ss examples/demo_aggregator.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_ss.so $(DFLAGS2) -D_SECRET_SHARING_=1 $(CCOPT)
demo_invert_ss: examples/demo_invert.c libtlcs_ss
	$(CC) -o  bin/demo_invert_ss examples/demo_invert.c $(IOPT)  $(LDFLAGS) ./lib/libtlcs_ss.so $(DFLAGS2) -D_SECRET_SHARING_=1 $(CCOPT)
tests: examples/tests.c cyclic_group.o err.o pairing.o prover.o verifier.o invert.o aggregate.o serialize.o simulated_loe.o global_bufs.o babyjubjub.o
	$(CC) -o  bin/tests src/cyclic_group.o src/err.o src/pairing.o src/prover.o src/verifier.o src/aggregate.o src/invert.o src/serialize.o src/babyjubjub.o src/tests/simulated_loe.o examples/tests.c src/global_bufs.o $(IOPT)  $(LDFLAGS) $(DFLAGS0) $(CCOPT)
clean:
	rm -f bin/tlcs /bin/tlcs_bls_g1 bin/tests *.o src/*.o examples/*.o /bin/demo* src/*.o lib/*.so

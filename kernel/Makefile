# Out-of-tree kernel module for the Sovereign plug-in gate.
#
#   make -C kernel        build the module against the running kernel's headers
#   make -C kernel test   build and run the user-space tests for the core logic
#   make -C kernel clean  remove build artefacts
#
# The modules cannot be loaded in this container (no CAP_SYS_MODULE). They are loaded and
# exercised in a real kernel by ../kernel/vm/run.sh. The core validation logic in sov_core.h
# is also executed without a kernel by `make test`.

obj-m := sovereign_gate.o sov_iommu.o sov_mldsa.o
obj-m += sov_ecdsa.o sov_hybrid.o
ccflags-y += -DSOV_HYBRID_SELFTEST -DSOV_ECDSA_SELFTEST

# The vendored pq-crystals reference is built into sov_mldsa.o, pinned to ML-DSA-87
# (Dilithium5 parameters). ccflags are per-directory, so they cannot leak to other modules.
sov_mldsa-y := sov_mldsa_wrap.o mldsa/verify_only.o mldsa/poly.o mldsa/polyvec.o \
               mldsa/ntt.o mldsa/reduce.o mldsa/rounding.o mldsa/packing.o \
               mldsa/fips202.o mldsa/symmetric-shake.o

ccflags-y += -DDILITHIUM_MODE=5 -I$(src)/mldsa/shim -I$(src)/mldsa

# The reference code is not -Werror clean against the kernel's stricter warnings, and
# rewriting it to be so would defeat the point of vendoring it unchanged.
CFLAGS_verify_only.o := -Wno-unused-parameter -Wno-sign-compare
CFLAGS_poly.o := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-but-set-variable
CFLAGS_polyvec.o := -Wno-unused-parameter -Wno-sign-compare
CFLAGS_packing.o := -Wno-unused-parameter -Wno-sign-compare
CFLAGS_fips202.o := -Wno-unused-parameter -Wno-sign-compare
CFLAGS_symmetric-shake.o := -Wno-unused-parameter -Wno-sign-compare

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# The host gcc often differs from the one that built the kernel, and Kbuild then looks for a
# compiler that is not installed. Override with CC=gcc-13 where available.
CC ?= gcc

all:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) modules

test: test_sov_core
	./test_sov_core

test_sov_core: test_sov_core.c sov_core.h
	$(CC) -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE -O2 -o $@ test_sov_core.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) clean
	rm -f test_sov_core

.PHONY: all test clean

# Out-of-tree kernel module for the Sovereign plug-in gate.
#
#   make -C kernel        build the module against the running kernel's headers
#   make -C kernel test   build and run the user-space tests for the core logic
#   make -C kernel clean  remove build artefacts
#
# The module COMPILES here but has never been loaded: this container has no CAP_SYS_MODULE.
# The core validation logic in sov_core.h *is* executed, by `make test`.

obj-m := sovereign_gate.o

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

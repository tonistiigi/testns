as_amd64 := as
as_x386 := as --32
as_armhf := arm-linux-gnueabihf-as
as_ppc64x := powerpc-linux-gnu-as
as_s390x := s390x-linux-gnu-as

ld_amd64 := ld
ld_x386 := ld -m elf_i386
ld_armhf := arm-linux-gnueabihf-ld
ld_ppc64x := powerpc-linux-gnu-ld
ld_s390x := s390x-linux-gnu-ld

all: amd64/pause armhf/pause ppc64x/pause s390x/pause x386/pause

builder:
	docker build -t testns-baseimage-builder .

%/pause: %/pause.s builder
	docker run --rm -v $(shell pwd):/src/fixtures -w /src/fixtures/$* \
		testns-baseimage-builder bash -c "${as_$*} -o pause.o pause.s && ${ld_$*} -o pause pause.o && rm pause.o"

.PHONY: builder all
target:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c trace.bpf.c -o trace.bpf.o
	bpftool gen skeleton trace.bpf.o > trace.skel.h
	clang -g -O2 -Wall -I . -c trace.c -o trace.o
	clang -Wall -O2 -g trace.o libbpf/build/libbpf.a -lelf -lz -o trace
	sudo ./trace
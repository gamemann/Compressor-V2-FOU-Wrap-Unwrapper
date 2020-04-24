CC = clang

all: kern
kern:
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/FOU_Wrap.c -o src/FOU_Wrap.bc
	llc -march=bpf -filetype=obj src/FOU_Wrap.bc -o src/FOU_Wrap.o

	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/FOU_Unwrap.c -o src/FOU_Unwrap.bc
	llc -march=bpf -filetype=obj src/FOU_Unwrap.bc -o src/FOU_Unwrap.o	 
clean:
	rm -f src/*.o
	rm -f src/*.bc
.PHONY: all
.DEFAULT: all
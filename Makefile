CC=gcc

CFLAGS=-Wall -O2 -Wno-unused-result -Wno-unused-variable -Wno-unused-but-set-variable
LDFLAGS=-ldl

all: tracee tracer

tracee: tracee.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tracer:	tracer.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm tracer tracee
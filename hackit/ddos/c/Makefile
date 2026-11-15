CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE
LDLIBS  ?= -pthread

all: stress_engine flood_engine

stress_engine: stress_engine.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

flood_engine: flood_engine.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f stress_engine flood_engine

.PHONY: all clean

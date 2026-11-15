CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE
LDLIBS  ?= -pthread
TLS_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
TLS_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

all: stress_engine flood_engine slowloris

stress_engine: stress_engine.c waf.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -o $@ $< $(LDLIBS) $(TLS_LIBS)

flood_engine: flood_engine.c waf.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -o $@ $< $(LDLIBS) $(TLS_LIBS)

slowloris: slowloris.c waf.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -o $@ $< $(LDLIBS) $(TLS_LIBS)

clean:
	rm -f stress_engine flood_engine slowloris *.sha256

.PHONY: all clean
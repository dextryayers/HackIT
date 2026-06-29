CC = gcc
CFLAGS = -O3 -march=native -mtune=native -flto -fPIC \
         -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
         -Wno-unused-variable -Wno-sign-compare -Wno-missing-field-initializers \
         -Wno-implicit-fallthrough -Wno-builtin-macro-redefined \
         -Iinclude
LDFLAGS = -shared -fPIC -ldl -lpthread -lm -Wl,--push-state,--no-as-needed -lssl -lcrypto -Wl,--pop-state

SRCS = $(wildcard *.c)
EXCLUDE = portstorm_c_dispatch.c os_detect.c
SCANNER_SRCS = $(filter-out $(EXCLUDE), $(SRCS))
SCANNER_OBJS = $(SCANNER_SRCS:.c=.o)
UTIL_SRCS = os_detect.c
UTIL_OBJS = os_detect.o
DISPATCH_OBJ = portstorm_c_dispatch.o
ALL_OBJS = $(SCANNER_OBJS) $(UTIL_OBJS) $(DISPATCH_OBJ)
TARGET = ../libportstorm_c.so

.PHONY: all clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) \
		-Dmain=$(subst .c,,$(notdir $<))_main \
		-c $< -o $@

os_detect.o: os_detect.c
	$(CC) $(CFLAGS) -c $< -o $@

portstorm_c_dispatch.o: portstorm_c_dispatch.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(ALL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "[+] Built $(TARGET) with $(words $(SCANNER_SRCS)) scanner modules + utilities"

clean:
	rm -f *.o $(TARGET)

inventory:
	@echo "=== PortStorm C Engine Inventory ==="
	@echo "Scanner modules: $(words $(SCANNER_SRCS))"
	@for f in $(SCANNER_SRCS); do echo "  $$f"; done
	@echo "Utility modules: $(words $(UTIL_SRCS))"
	@for f in $(UTIL_SRCS); do echo "  $$f"; done
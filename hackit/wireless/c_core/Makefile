# HackIT Wireless C/C++ Core — standalone build (no CMake required).
#
# Targets
#   make            → build/libhackit_wireless_c.so + build/libhackit_wireless_c.a
#                     + build/hackit-c (standalone CLI)
#   make shared     → shared library only
#   make static     → static library only
#   make cli        → hackit-c standalone binary only
#   make clean      → remove build objects
#   make -j$(nproc)
#
# Dependency detection is automatic. If libpcap is missing, the tree builds
# but frame injection will return false (callers fall back to native
# AF_PACKET / raw sockets, which the engines already do).

CC      ?= gcc
CXX     ?= g++
AR      ?= ar
BUILD   ?= build

CFLAGS_COMMON := -Wextra -Wno-unused-parameter -Wno-sign-compare \
                 -D_DEFAULT_SOURCE -D_GNU_SOURCE -DHACKIT_BUILD_STATIC \
                 -std=gnu11 -O2 -fPIC -Iinclude -Iinclude/nlohmann
CXXFLAGS_COMMON := -Wextra -Wno-unused-parameter -Wno-sign-compare \
                   -D_DEFAULT_SOURCE -D_GNU_SOURCE \
                   -std=gnu++17 -O2 -fPIC -Iinclude -Iinclude/nlohmann

LDLIBS   := -lpthread -lm

# libpcap detection
PCAP_INC := $(wildcard /usr/include/pcap.h /usr/local/include/pcap.h)
ifneq ($(PCAP_INC),)
  CFLAGS_COMMON   += -DHACKIT_HAS_PCAP
  CXXFLAGS_COMMON += -DHACKIT_HAS_PCAP
  LDLIBS          += -lpcap
endif

# libnl-3 detection (optional; interface control uses iw fallback otherwise)
NL3_INC := $(wildcard /usr/include/libnl3/netlink/netlink.h /usr/include/netlink/netlink.h)
ifneq ($(NL3_INC),)
  CFLAGS_COMMON   += -DHACKIT_HAS_NL3
  CXXFLAGS_COMMON += -DHACKIT_HAS_NL3
  ifneq ($(wildcard /usr/include/libnl3),)
    CFLAGS_COMMON   += -I/usr/include/libnl3
    CXXFLAGS_COMMON += -I/usr/include/libnl3
  endif
endif

C_SRCS   := $(wildcard src/*.c)
CXX_SRCS := $(wildcard src/*.cpp)
C_OBJS   := $(patsubst src/%.c,$(BUILD)/%.o,$(C_SRCS))
CXX_OBJS := $(patsubst src/%.cpp,$(BUILD)/%.cpp.o,$(CXX_SRCS))
ALL_OBJS := $(C_OBJS) $(CXX_OBJS)

LIB_SO    := $(BUILD)/libhackit_wireless_c.so
LIB_A     := $(BUILD)/libhackit_wireless_c.a
CLI_BIN   := $(BUILD)/hackit-c
CLI_SRC   := cli/main.c

.PHONY: all shared static cli clean dirs

all: dirs shared static cli

dirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | dirs
	$(CC) $(CFLAGS_COMMON) -c $< -o $@

$(BUILD)/%.cpp.o: src/%.cpp | dirs
	$(CXX) $(CXXFLAGS_COMMON) -c $< -o $@

shared: $(LIB_SO)
static: $(LIB_A)

$(LIB_SO): $(ALL_OBJS) | dirs
	$(CXX) -shared -Wl,-soname,libhackit_wireless_c.so -o $@ $(ALL_OBJS) $(LDLIBS)

$(LIB_A): $(ALL_OBJS) | dirs
	$(AR) rcs $@ $(ALL_OBJS)

cli: $(CLI_BIN)

$(CLI_BIN): $(ALL_OBJS) $(CLI_SRC) | dirs
	$(CC) $(CFLAGS_COMMON) -o $@ $(CLI_SRC) $(LIB_A) $(LDLIBS)

clean:
	rm -rf $(BUILD)

# Convenience: copy artifacts next to the python bridge so it finds them
install: all
	@mkdir -p ..
	@cp -f $(LIB_SO) .. 2>/dev/null || true
	@cp -f $(CLI_BIN) .. 2>/dev/null || true
	@echo "Copied $(LIB_SO) and $(CLI_BIN) to parent dir"

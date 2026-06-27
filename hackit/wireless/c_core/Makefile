CC = gcc
CXX = g++
CFLAGS = -std=gnu11 -O2 -fPIC -Iinclude -D_GNU_SOURCE -D_DEFAULT_SOURCE
CXXFLAGS = -std=gnu++17 -O2 -fPIC -Iinclude -D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS = -shared

C_SOURCES = \
	src/packet_capture.c \
	src/wifi_stack.c \
	src/raw_networking.c \
	src/wireless_frame.c \
	src/crypto_security.c \
	src/adapter_detection.c \
	src/interface_control.c \
	src/packet_injector.c \
	src/deauth_engine.c \
	src/deauth_engine_v1.c \
	src/deauth_engine_v2.c \
	src/pmkid_harvest.c \
	src/wpa3_sae.c \
	src/beacon_flood.c \
	src/eviltwin_v1.c \
	src/eviltwin_v2.c \
	src/eviltwin_v3.c \
	src/client_probe.c \
	src/channel_hopper.c \
	src/banner_grabber.c \
	src/oui_lookup.c \
	src/web_bridge_impl.c

CXX_SOURCES = \
	src/signal_processing.cpp \
	src/frame_parser.cpp \
	src/eapol_analyzer.cpp \
	src/spectrum_scanner.cpp \
	src/wps_attack.cpp \
	src/wep_cracker.cpp \
	src/packet_forge.cpp \
	src/key_manager.cpp \
	src/offensive_plus.cpp \
	src/cpp_deauth_engine.cpp \
	src/cpp_deauth_ultra.cpp \
	src/eviltwin_cpp_v1.cpp \
	src/eviltwin_cpp_v2.cpp \
	src/eviltwin_cpp_v3.cpp

C_OBJ = $(C_SOURCES:.c=.o)
CXX_OBJ = $(CXX_SOURCES:.cpp=.o)
OBJ = $(C_OBJ) $(CXX_OBJ)

LIB_STATIC = libhackit_wireless_c.a
LIB_SHARED = libhackit_wireless_c.so

.PHONY: all static shared clean

all: static shared

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

static: $(OBJ)
	ar rcs $(LIB_STATIC) $(OBJ)

shared: $(OBJ)
	$(CXX) $(LDFLAGS) -o $(LIB_SHARED) $(OBJ)

eviltwin-inject: eviltwin_inject.c
	$(CC) -std=gnu11 -O2 -static -pthread -o $@ $<
	$(info [BUILD] eviltwin-inject ready)

deauth-inject: deauth_inject.c
	$(CC) -std=gnu11 -O2 -static -o $@ $<
	$(info [BUILD] deauth-inject ready)

clean:
	rm -f $(OBJ) $(LIB_STATIC) $(LIB_SHARED) eviltwin-inject deauth-inject

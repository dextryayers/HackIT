cmake_minimum_required(VERSION 3.10)
project(HackITWirelessCCore C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include directories
include_directories(include)

# Detect pcap availability
find_path(PCAP_INCLUDE_DIR pcap.h
    PATHS /usr/include /usr/local/include "C:/WpdPack/Include" "C:/Npcap/Include"
)
find_library(PCAP_LIBRARY pcap
    PATHS /usr/lib /usr/local/lib "C:/WpdPack/Lib" "C:/Npcap/Lib"
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    message(STATUS "pcap found: ${PCAP_LIBRARY}")
    add_definitions(-DHACKIT_HAS_PCAP)
    include_directories(${PCAP_INCLUDE_DIR})
    link_directories(${PCAP_LIBRARY})
else()
    message(STATUS "pcap NOT found - frame injection/PMKID harvest will use stubs")
endif()

# Windows Compilation Mode
add_library(hackit_wireless_c STATIC
    src/packet_capture.c
    src/wifi_stack.c
    src/raw_networking.c
    src/wireless_frame.c
    src/crypto_security.c
    src/adapter_detection.c
    src/interface_control.c
    src/packet_injector.c
    src/deauth_engine.c
    src/pmkid_harvest.c
    src/wpa3_sae.c
    src/beacon_flood.c
    src/client_probe.c
    src/channel_hopper.c
    src/signal_processing.cpp
    src/frame_parser.cpp
    src/eapol_analyzer.cpp
    src/spectrum_scanner.cpp
    src/wps_attack.cpp
    src/wep_cracker.cpp
    src/packet_forge.cpp
    src/key_manager.cpp
    src/tcp_scanner.c
    src/syn_scanner.c
    src/banner_grabber.c
)

target_include_directories(hackit_wireless_c PUBLIC include)


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
    PATHS /usr/lib /usr/local/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu "C:/WpdPack/Lib" "C:/Npcap/Lib"
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    message(STATUS "pcap found: ${PCAP_LIBRARY}")
    add_definitions(-DHACKIT_HAS_PCAP)
    include_directories(${PCAP_INCLUDE_DIR})
else()
    message(STATUS "pcap NOT found - frame injection/PMKID harvest will use stubs")
endif()

# Detect libnl-3 on Linux
if(UNIX)
    find_path(NL3_INCLUDE_DIR netlink/netlink.h
        PATHS /usr/include /usr/local/include /usr/include/libnl3
    )
    find_library(NL3_LIBRARY nl-3
        PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib
    )
    if(NL3_INCLUDE_DIR AND NL3_LIBRARY)
        message(STATUS "libnl-3 found: ${NL3_LIBRARY}")
        add_definitions(-DHACKIT_HAS_NL3)
        include_directories(${NL3_INCLUDE_DIR})
    else()
        message(STATUS "libnl-3 NOT found - some interface control will use stubs")
    endif()
endif()

# Common sources
set(CORE_SOURCES
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

# ── Static library (for Rust FFI via build.rs) ──
add_library(hackit_wireless_c STATIC ${CORE_SOURCES})
target_include_directories(hackit_wireless_c PUBLIC include)
target_compile_definitions(hackit_wireless_c PRIVATE HACKIT_BUILD_STATIC)

if(PCAP_LIBRARY)
    target_link_libraries(hackit_wireless_c PRIVATE ${PCAP_LIBRARY})
endif()
if(NL3_LIBRARY)
    target_link_libraries(hackit_wireless_c PRIVATE ${NL3_LIBRARY})
endif()

# ── Shared library (for Python engine_bridge via ctypes) ──
add_library(hackit_wireless_c_shared SHARED ${CORE_SOURCES})
target_include_directories(hackit_wireless_c_shared PUBLIC include)

# Set output name so the .so filename is libhackit_wireless_c.so
set_target_properties(hackit_wireless_c_shared PROPERTIES
    OUTPUT_NAME "hackit_wireless_c"
    PREFIX "lib"
    POSITION_INDEPENDENT_CODE ON
)

if(PCAP_LIBRARY)
    target_link_libraries(hackit_wireless_c_shared PRIVATE ${PCAP_LIBRARY})
endif()
if(NL3_LIBRARY)
    target_link_libraries(hackit_wireless_c_shared PRIVATE ${NL3_LIBRARY})
endif()
if(WIN32)
    target_link_libraries(hackit_wireless_c_shared PRIVATE wpcap)
endif()

# ── Install / post-build copy ──
# Copy shared lib to build/lib/ for engine_bridge discovery
add_custom_command(TARGET hackit_wireless_c_shared POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/lib"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:hackit_wireless_c_shared>"
        "${CMAKE_BINARY_DIR}/lib/$<TARGET_FILE_NAME:hackit_wireless_c_shared>"
    COMMENT "Copying shared library to build/lib/"
)

# Copy static lib so Rust build.rs can find it in build/
add_custom_command(TARGET hackit_wireless_c POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:hackit_wireless_c>"
        "${CMAKE_BINARY_DIR}/$<TARGET_FILE_NAME:hackit_wireless_c>"
    COMMENT "Copying static library to build/"
)


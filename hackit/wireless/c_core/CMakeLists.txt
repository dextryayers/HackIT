cmake_minimum_required(VERSION 3.10)
project(HackITWirelessCCore C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include directories
include_directories(include)

# Windows Compilation Mode
add_library(hackit_wireless_c STATIC
    src/packet_capture.c
    src/wifi_stack.c
    src/raw_networking.c
    src/wireless_frame.c
    src/crypto_security.c
    src/adapter_detection.c
    src/interface_control.c
    src/signal_processing.cpp
    src/frame_parser.cpp
)

target_include_directories(hackit_wireless_c PUBLIC include)

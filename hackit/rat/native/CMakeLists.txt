cmake_minimum_required(VERSION 3.22)
project(hackit_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CORE
    src/aead.cpp
    src/transport.cpp
    src/probe.cpp)

if(ANDROID)
    add_library(hackit SHARED ${CORE} src/jni.cpp)
    target_include_directories(hackit PRIVATE include)
    target_compile_options(hackit PRIVATE -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)
    find_library(log-lib log)
    if(log-lib)
        target_link_libraries(hackit ${log-lib})
    endif()
else()
    add_executable(stalker ${CORE} src/stalker_main.cpp)
    target_include_directories(stalker PRIVATE include)
    target_compile_options(stalker PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

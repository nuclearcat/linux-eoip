cmake_minimum_required(VERSION 3.13)

project(linux-eoip
        VERSION 0.4
        DESCRIPTION "Mikrotik-compatible EoIP and VIP tunnels for Linux"
        LANGUAGES C)

include(GNUInstallDirs)

# tun/tap, raw sockets and CPU affinity are all Linux interfaces.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR
        "linux-eoip targets Linux only (tun/tap, raw sockets, CPU affinity), "
        "but CMAKE_SYSTEM_NAME is \"${CMAKE_SYSTEM_NAME}\".")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 Debug Release RelWithDebInfo MinSizeRel)
endif()

# ---------------------------------------------------------------------------
# liblzo2, used by vip for the per-tunnel "compression" option
# ---------------------------------------------------------------------------
set(WITH_LZO "AUTO" CACHE STRING
    "LZO compression support in vip: ON (required), OFF, or AUTO (use if found)")
set_property(CACHE WITH_LZO PROPERTY STRINGS AUTO ON OFF)

if(NOT WITH_LZO STREQUAL "OFF")
    find_path(LZO_INCLUDE_DIR NAMES lzo/lzo1x.h)
    find_library(LZO_LIBRARY NAMES lzo2)
    mark_as_advanced(LZO_INCLUDE_DIR LZO_LIBRARY)

    if(LZO_INCLUDE_DIR AND LZO_LIBRARY)
        set(HAVE_LIBLZO2 1)
        message(STATUS "LZO compression: enabled (${LZO_LIBRARY})")
    elseif(WITH_LZO STREQUAL "ON")
        message(FATAL_ERROR
            "WITH_LZO=ON but liblzo2 was not found. Install the development "
            "package (liblzo2-dev / lzo-devel) or configure with -DWITH_LZO=OFF.")
    else()
        message(STATUS "LZO compression: disabled (liblzo2 not found)")
    endif()
else()
    message(STATUS "LZO compression: disabled (WITH_LZO=OFF)")
endif()

# ---------------------------------------------------------------------------
# recvmmsg fills the whole receive ring in one syscall instead of one per
# packet. Probe it the way the sources actually compile: they define
# _GNU_SOURCE themselves, except on uClibc, where recvmmsg stays hidden.
# ---------------------------------------------------------------------------
include(CheckCSourceCompiles)
check_c_source_compiles("
#ifndef __UCLIBC__
#define _GNU_SOURCE
#endif
#include <sys/socket.h>
#include <sys/uio.h>
int main(void) {
    struct mmsghdr msgs[1];
    return recvmmsg(0, msgs, 1, 0, (void *)0) < 0;
}
" HAVE_RECVMMSG)

if(HAVE_RECVMMSG)
    message(STATUS "Batched receive: recvmmsg")
else()
    message(STATUS "Batched receive: unavailable, falling back to recvfrom")
endif()

# sendmmsg is the transmit-side counterpart. Without it the transmit path
# still batches its reads and falls back to one sendmsg per packet, which
# takes the same msghdr, so only the send call differs.
check_c_source_compiles("
#ifndef __UCLIBC__
#define _GNU_SOURCE
#endif
#include <sys/socket.h>
#include <sys/uio.h>
int main(void) {
    struct mmsghdr msgs[1];
    return sendmmsg(0, msgs, 1, 0) < 0;
}
" HAVE_SENDMMSG)

if(HAVE_SENDMMSG)
    message(STATUS "Batched send: sendmmsg")
else()
    message(STATUS "Batched send: unavailable, falling back to sendmsg")
endif()

find_package(Threads REQUIRED)

# Must precede the subdirectories: add_compile_options only affects
# targets created after the call.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

add_subdirectory(third_party/minini)
add_subdirectory(src)

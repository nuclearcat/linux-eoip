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
# packet.
# ---------------------------------------------------------------------------
include(CheckCSourceCompiles)
check_c_source_compiles("
#define _GNU_SOURCE
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
#define _GNU_SOURCE
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

# CPU affinity is optional: the daemons pin the receive thread to CPU 0 and
# each transmit thread to one core, and run unpinned where that is missing.
check_c_source_compiles("
#define _GNU_SOURCE
#include <pthread.h>
int main(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}
" HAVE_PTHREAD_SETAFFINITY_NP)

if(HAVE_PTHREAD_SETAFFINITY_NP)
    message(STATUS "CPU affinity: available")
else()
    message(STATUS "CPU affinity: unavailable, threads run unpinned")
endif()

# ---------------------------------------------------------------------------
# Buffer sizing. These are memory against throughput tradeoffs for the device
# being targeted, not properties of the libc, so set them rather than letting
# anything guess. Defaults suit a machine with memory to spare; shrink
# RING_SLOTS and TX_BATCH first on a small embedded target, they dominate.
# ---------------------------------------------------------------------------
set(EOIP_MAXPAYLOAD 2048  CACHE STRING "eoip: largest tunnelled payload, bytes")
set(VIP_MAXPAYLOAD  65536 CACHE STRING "vip: largest tunnelled payload, bytes")
set(RING_SLOTS      64    CACHE STRING "Receive ring depth, slots of MAXPAYLOAD each")
set(TX_BATCH        16    CACHE STRING "eoip: transmit batch depth, per tunnel")

foreach(var EOIP_MAXPAYLOAD VIP_MAXPAYLOAD RING_SLOTS TX_BATCH)
    if(NOT "${${var}}" MATCHES "^[1-9][0-9]*$")
        message(FATAL_ERROR "${var} must be a positive integer, got \"${${var}}\"")
    endif()
endforeach()

math(EXPR _eoip_ring "${EOIP_MAXPAYLOAD} * ${RING_SLOTS} / 1024")
math(EXPR _vip_ring  "${VIP_MAXPAYLOAD} * ${RING_SLOTS} / 1024")
message(STATUS "Receive ring: eoip ${_eoip_ring}KB, vip ${_vip_ring}KB")

find_package(Threads REQUIRED)

# Must precede the subdirectories: add_compile_options only affects
# targets created after the call.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

add_subdirectory(third_party/minini)
add_subdirectory(src)

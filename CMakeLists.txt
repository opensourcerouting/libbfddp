cmake_minimum_required(VERSION 3.10)

project(bfddp VERSION 0.1.0)

add_library(
  libbfddp
  libbfddp/bfddp.c
  libbfddp/bfddp_extra.c
  )

add_library(
  vbfd
  soft_bfddpd/debug.c
  soft_bfddpd/events.c
  soft_bfddpd/openbsd-tree.c
  soft_bfddpd/packet.c
  soft_bfddpd/session.c
  )

target_include_directories(vbfd PUBLIC libbfddp)

add_executable(
  bfddpd
  bfddpd/bfddpd.c
  )

target_link_libraries(bfddpd libbfddp)
target_include_directories(bfddpd PUBLIC libbfddp)

# Software based BFD data plane.
add_executable(
  soft_bfddpd
  soft_bfddpd/bfddpd.c
  soft_bfddpd/debug.c
  soft_bfddpd/events.c
  soft_bfddpd/openbsd-tree.c
  soft_bfddpd/packet.c
  soft_bfddpd/session.c
  )

target_link_libraries(soft_bfddpd libbfddp)
target_include_directories(soft_bfddpd PUBLIC libbfddp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")

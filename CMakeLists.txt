cmake_minimum_required(VERSION 3.10)

project(bfddp VERSION 0.1.0)

add_library(
  libbfddp
  libbfddp/bfddp.c
  )

add_executable(
  bfddpd
  bfddpd/bfddpd.c
  )

target_link_libraries(bfddpd libbfddp)
target_include_directories(bfddpd PUBLIC libbfddp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")

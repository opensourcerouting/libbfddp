BFD Data Plane
==============

This is a implementation of software based BFD data plane library to be used
as base for hardware implementations.

The project uses CMake so you can build the source out-of-the-tree like this:

```sh
# Enter source code directory:
cd libbfddp

# Create build dir separated from source:
mkdir build
cd build

# Generate makefile (for production):
cmake -DCMAKE_BUILD_TYPE=Release ..
# Generate makefile (for debugging):
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Build library and sample daemons:
make
```

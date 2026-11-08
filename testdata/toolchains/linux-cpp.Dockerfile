# Both architectures use the same immutable official GCC 14 manifest index.
# The image already contains g++, binutils, glibc and libstdc++; no apt setup.
FROM gcc@sha256:a257536c9b7a0ee193c1880f2d691358d2c9760ef0ede3ee741aa243789743c7

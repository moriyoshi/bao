# SPDX-License-Identifier: Apache-2.0
# Immutable multiarch GCC base keeps libstdc++ available for both producers.
# Clang and all newly installed dependencies resolve from one dated Debian
# snapshot. Recommends (including Python and clang-tools) are not installed.
FROM gcc@sha256:a257536c9b7a0ee193c1880f2d691358d2c9760ef0ede3ee741aa243789743c7

ARG DEBIAN_SNAPSHOT=20261108T000000Z
ARG CLANG_DEBIAN_VERSION=1:19.1.7-3+b1
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s/ trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends "clang-19=$CLANG_DEBIAN_VERSION" \
    && rm -rf /var/lib/apt/lists/*
RUN ln -s /usr/bin/clang++-19 /usr/local/bin/clang++

# Use clang++ --gcc-toolchain=/usr/local -stdlib=libstdc++ explicitly in
# producer commands. No alternative C++ runtime or compiler wrapper is hidden.

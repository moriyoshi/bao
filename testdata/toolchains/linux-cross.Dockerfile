# Maintainer-only cross compiler and QEMU image; verification uses --pull=never
# and --network=none. Build once, before running the offline integration suite.
FROM --platform=linux/arm64 rust@sha256:38618e9e8971729f1b9f25bf93aaff2dc7b7ff22a6cde1930d96fb8226756029
ARG DEBIAN_SNAPSHOT=20261108T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s/ trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
    gcc-loongarch64-linux-gnu=4:14.2.0-1 \
    gcc-powerpc64le-linux-gnu=4:14.2.0-1 \
    gcc-x86-64-linux-gnu=4:14.2.0-1 \
    gcc-14-loongarch64-linux-gnu=14.2.0-19cross1 \
    gcc-14-powerpc64le-linux-gnu=14.2.0-19cross1 \
    gcc-14-x86-64-linux-gnu=14.2.0-19cross1 \
    g++-loongarch64-linux-gnu=4:14.2.0-1 \
    g++-powerpc64le-linux-gnu=4:14.2.0-1 \
    g++-x86-64-linux-gnu=4:14.2.0-1 \
    g++-14-loongarch64-linux-gnu=14.2.0-19cross1 \
    g++-14-powerpc64le-linux-gnu=14.2.0-19cross1 \
    g++-14-x86-64-linux-gnu=14.2.0-19cross1 \
    clang-19=1:19.1.7-3+b1 \
    binutils-loongarch64-linux-gnu=2.44-3 \
    binutils-powerpc64le-linux-gnu=2.44-3 \
    binutils-x86-64-linux-gnu=2.44-3 \
    libc6-dev-loong64-cross=2.41-11cross1 \
    libc6-dev-ppc64el-cross=2.41-11cross1 \
    libc6-dev-amd64-cross=2.41-11cross1 \
    qemu-user=1:10.0.13+ds-0+deb13u1 \
    && rm -rf /var/lib/apt/lists/*
RUN ln -s /usr/bin/clang++-19 /usr/local/bin/clang++
RUN rustup target add loongarch64-unknown-linux-gnu powerpc64le-unknown-linux-gnu x86_64-unknown-linux-gnu

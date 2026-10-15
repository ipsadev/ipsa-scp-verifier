FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS core

ARG CORE_TAG=v27.1.0
ARG CORE_COMMIT=3589a696b0d4ef5a2cf2124e349c671d71886d9c
ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256_X86_64=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
ARG RUSTUP_SHA256_AARCH64=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git curl \
      build-essential clang pkg-config \
      autoconf automake libtool bison flex \
      libpq-dev libunwind-dev \
      python3 perl sed \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${CORE_TAG} \
      --recurse-submodules --shallow-submodules \
      https://github.com/stellar/stellar-core.git /src/stellar-core \
    && test "$(git -C /src/stellar-core rev-parse HEAD)" = "${CORE_COMMIT}"

RUN arch="$(uname -m)" \
    && case "$arch" in \
         x86_64) sum="${RUSTUP_SHA256_X86_64}" ;; \
         aarch64) sum="${RUSTUP_SHA256_AARCH64}" ;; \
         *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
       esac \
    && curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init \
         "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" \
    && echo "${sum}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --no-modify-path \
    && rm /tmp/rustup-init
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src/stellar-core
RUN ./autogen.sh
RUN CC=clang CXX=clang++ ./configure --disable-tests

COPY oracle.cpp stubs.cpp build-oracle.sh /work/
RUN chmod +x /work/build-oracle.sh && CORE=/src/stellar-core OUT=/usr/local/bin/oracle \
      /work/build-oracle.sh

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
COPY --from=core /usr/local/bin/oracle /usr/local/bin/oracle
ENTRYPOINT ["/usr/local/bin/oracle"]

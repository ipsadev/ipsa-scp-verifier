FROM ubuntu:24.04 AS core

ARG CORE_TAG=v27.1.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git curl \
      build-essential clang pkg-config \
      autoconf automake libtool bison flex \
      libpq-dev libunwind-dev \
      python3 perl sed \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${CORE_TAG} \
      --recurse-submodules --shallow-submodules \
      https://github.com/stellar/stellar-core.git /src/stellar-core

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --no-modify-path
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src/stellar-core
RUN ./autogen.sh
RUN CC=clang CXX=clang++ ./configure --disable-tests

COPY oracle.cpp stubs.cpp build-oracle.sh /work/
RUN chmod +x /work/build-oracle.sh && CORE=/src/stellar-core OUT=/usr/local/bin/oracle \
      /work/build-oracle.sh

FROM ubuntu:24.04
COPY --from=core /usr/local/bin/oracle /usr/local/bin/oracle
ENTRYPOINT ["/usr/local/bin/oracle"]

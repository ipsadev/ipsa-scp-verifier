FROM rust:1.91-slim-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tools ./tools
COPY tests ./tests

RUN cargo build --release --bin scp-verify

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 verifier

COPY --from=build /src/target/release/scp-verify /usr/local/bin/scp-verify

USER verifier
EXPOSE 8110

ENTRYPOINT ["/usr/local/bin/scp-verify"]
CMD ["--serve", "8110"]

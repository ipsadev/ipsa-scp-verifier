FROM rust:1.91-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tools ./tools
COPY tests ./tests

RUN cargo build --locked --release --bin ipsa-scp-verify

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 verifier

COPY --from=build /src/target/release/ipsa-scp-verify /usr/local/bin/ipsa-scp-verify

USER verifier
EXPOSE 8110

ENTRYPOINT ["/usr/local/bin/ipsa-scp-verify"]
CMD ["--serve", "8110"]

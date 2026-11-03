# The 05 console: one image; its data is one SQLite file on the /data volume. Build from product/:
# Base images are pinned by digest: update them on purpose, not by accident.
#   docker build -f crates/console/Dockerfile .

# The policy editor's checks, compiled to WebAssembly for the browser (the console cannot read a
# team's policy). wasm-bindgen-cli must match the wasm-bindgen in Cargo.lock.
FROM rust:1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS wasm
RUN rustup target add wasm32-unknown-unknown && cargo install wasm-bindgen-cli --version 0.2.130 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p use05-policy-wasm --target wasm32-unknown-unknown \
 && wasm-bindgen --target web --out-dir /wasm target/wasm32-unknown-unknown/release/use05_policy_wasm.wasm

FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS web
WORKDIR /web
COPY console-web/package.json console-web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console-web/ ./
COPY --from=wasm /wasm src/wasm
# The browser's crypto is checked against the helper's (Rust) vectors.
COPY crates/cloud/tests/vectors.json /crates/cloud/tests/vectors.json
RUN npm test && npm run build

FROM rust:1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS server
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p use05-console

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 console
WORKDIR /app
COPY --from=server /src/target/release/use05-console /app/use05-console
COPY --from=web /web/dist /app/web/dist
# Mount a volume at /data (docker run -v console-data:/data; on Railway, a service volume). No
# VOLUME line: some hosts refuse it, and the mount is the host's to make.
RUN mkdir /data && chown console /data
USER console
ENV WEB_DIR=/app/web/dist PORT=8080 DATABASE=/data/console.db
EXPOSE 8080
CMD ["/app/use05-console"]

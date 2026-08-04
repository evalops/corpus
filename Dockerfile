# syntax=docker/dockerfile:1

FROM rust:1.97-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY docs/openapi.json ./docs/openapi.json

RUN cargo build --locked --release -p corpus-server -p corpus-scanner

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/target/release/corpus-server /usr/local/bin/corpus-server
COPY --from=build /src/target/release/corpus-scanner /usr/local/bin/corpus-scanner

ENV CORPUS_SCANNER_BIN=/usr/local/bin/corpus-scanner

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/corpus-server"]

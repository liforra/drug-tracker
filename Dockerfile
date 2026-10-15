# Two stages. The Rust toolchain is ~1.5 GB and none of it is needed to run the
# resulting binary, so it stays in the build stage.
FROM rust:1-slim-bookworm AS build
WORKDIR /src

# rusqlite is used with the `bundled` feature, so SQLite itself is compiled from
# source here. That is the only reason this layer needs a C toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# The whole workspace is copied because cargo resolves every member's manifest even
# when only one package is built. The client crates are parsed, never compiled.
COPY . .
RUN cargo build --release -p tracker-server

FROM debian:bookworm-slim
# No ca-certificates: the server makes no outbound TLS connections. Nothing to trust.
COPY --from=build /src/target/release/tracker-server /usr/local/bin/tracker-server

# Runs as an unprivileged uid set by compose, matching the owner of the bind-mounted
# data directory. There is deliberately no passwd entry -- nothing here needs one.
ENV TRACKER_DB=/data/tracker-server.db \
    TRACKER_BIND=0.0.0.0:8747 \
    TRACKER_REQUIRE_TUNNEL=1
EXPOSE 8747
ENTRYPOINT ["tracker-server"]
CMD ["serve"]

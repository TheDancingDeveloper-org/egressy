FROM rust:1.97-alpine3.23 AS builder
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY openapi ./openapi
COPY ui/dist ./ui/dist
RUN cargo build --locked --release --bins

# Alpine 3.23 openresolv rejects Docker's managed /etc/resolv.conf during
# wg-quick startup. Keep the known-good runtime while compiling with Rust 1.97.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl iproute2 nftables openssl wireguard-tools openresolv \
    && addgroup -S egressy \
    && adduser -S -G egressy egressy
COPY --from=builder /src/target/release/egressy /usr/local/bin/egressy
COPY --from=builder /src/target/release/egressy-probe /usr/local/bin/egressy-probe
COPY --from=builder /src/target/release/egressy-isolation-agent /usr/local/bin/egressy-isolation-agent
ENTRYPOINT ["/usr/local/bin/egressy"]
CMD ["run"]

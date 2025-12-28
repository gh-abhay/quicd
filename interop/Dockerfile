# Build QuicD binary
FROM rust:1 AS build

# Install eBPF build dependencies
RUN apt-get update && \
    apt-get install -y cmake llvm-19-dev libclang-19-dev libpolly-19-dev && \
    rm -rf /var/lib/apt/lists/*

# Install nightly toolchain with rust-src component
RUN rustup toolchain install nightly --component rust-src

# Install bpf-linker
RUN cargo install bpf-linker

WORKDIR /build

COPY Cargo.toml ./
COPY ebpf/ ./ebpf/
COPY quicd/ ./quicd/
COPY quicd-quic/ ./quicd-quic/
COPY quicd-x/ ./quicd-x/
COPY quicd-qpack/ ./quicd-qpack/
COPY quicd-h3/ ./quicd-h3/
COPY quicd-hq-interop/ ./quicd-hq-interop/

RUN cargo build --release

# Build simulator endpoint image
FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=build \
     /build/target/release/quicd \
     ./
COPY interop/quicd.toml ./
COPY interop/server-cert/ ./server-cert/
COPY interop/run_endpoint.sh ./

RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]

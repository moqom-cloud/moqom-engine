# The relay's image.
#
# Built from the workspace root, because the relay depends on three sibling
# crates in it -- moqom-proto, moqom-transport, moqom-rans -- and a context
# scoped to moqom-relay/ cannot see them.
#
#   docker build -t moqom-relay .
#
# Prefer Cloud Build for anything that will actually be deployed. GKE and the
# relay MIG are amd64, a Mac is not, and a Rust build under QEMU takes tens of
# minutes to produce the same bytes a native builder produces in a few.

FROM rust:1.97.1-bookworm AS build

WORKDIR /src

# Manifests first, so the dependency build survives a change to our own source.
# The dummy targets exist only to give cargo something to compile: it will not
# resolve a workspace whose members have no entry point.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./

# The patched quinn the workspace depends on by path. Copied whole and early:
# it changes about as often as the manifests do, and cargo cannot resolve the
# workspace without it.
COPY vendor vendor

COPY moqom-proto/Cargo.toml moqom-proto/
COPY moqom-rans/Cargo.toml moqom-rans/
COPY moqom-rans-ffi/Cargo.toml moqom-rans-ffi/
COPY moqom-relay/Cargo.toml moqom-relay/
COPY moqom-transport/Cargo.toml moqom-transport/
COPY moqom-client/Cargo.toml moqom-client/
COPY moqom-cli/Cargo.toml moqom-cli/
RUN for crate in moqom-proto moqom-rans moqom-rans-ffi moqom-relay moqom-transport moqom-client moqom-cli; do \
        mkdir -p "$crate/src" && echo "fn main() {}" > "$crate/src/main.rs" && \
        touch "$crate/src/lib.rs"; \
    done && \
    mkdir -p moqom-relay/src/bin && echo "fn main() {}" > moqom-relay/src/bin/relay.rs && \
    cargo build --release --bin moqom-relay 2>/dev/null || true

# The real source. Removing the built artefacts of the dummy crates is
# necessary: cargo decides what to rebuild from mtimes, and without this it
# keeps the stubs.
COPY moqom-proto moqom-proto
COPY moqom-rans moqom-rans
COPY moqom-rans-ffi moqom-rans-ffi
COPY moqom-relay moqom-relay
COPY moqom-transport moqom-transport
COPY moqom-client moqom-client
COPY moqom-cli moqom-cli
RUN find target/release -maxdepth 1 -name 'moqom*' -exec rm -rf {} + 2>/dev/null || true

ARG VERSION=dev
ENV MOQOM_BUILD_VERSION=${VERSION}
RUN cargo build --release -p moqom-relay --bin moqom-relay && \
    strip target/release/moqom-relay

# cc rather than static, because the relay links against the system's TLS and
# resolver through the standard library's glibc paths. Nonroot for the same
# reason the control plane's image is: the relay binds 443 through the host's
# network namespace, not through a privileged port on its own.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/target/release/moqom-relay /moqom-relay

# 443 is QUIC, over UDP. 8081 is the admin surface: metrics, /healthz and
# /readyz, which the load balancer and the instance group read over TCP.
EXPOSE 443/udp 8081/tcp

USER nonroot:nonroot
ENTRYPOINT ["/moqom-relay"]

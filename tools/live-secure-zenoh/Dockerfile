# Exact Rust 1.96.0 Bookworm multi-platform image. The campaign manifest also
# records the platform-specific child digest selected by Docker.
FROM docker.io/library/rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS build

RUN --mount=type=bind,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    CARGO_TARGET_DIR=/build/target cargo build \
      --manifest-path /src/Cargo.toml \
      --locked \
      --release \
      --package haldir-transport-zenoh \
      --example live_secure_acl_campaign \
      --features live-zenoh

FROM docker.io/library/rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc
COPY --from=build /build/target/release/examples/live_secure_acl_campaign /usr/local/bin/haldir-live-secure-acl-campaign
ENTRYPOINT ["/usr/local/bin/haldir-live-secure-acl-campaign"]

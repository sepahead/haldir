# Exact Rust 1.96.0 Bookworm multi-platform image. The generated metadata records
# the platform-specific child digest selected by Docker.
FROM docker.io/library/rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS build

RUN --mount=type=bind,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    CARGO_TARGET_DIR=/build/target cargo build \
      --manifest-path /src/Cargo.toml \
      --locked \
      --release \
      --package haldir-gate \
      --example live_gate_dev_fixture_provision \
      --example live_gate_dev_bind_shutdown \
      --features live-gate-dev-smoke

FROM docker.io/library/rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc
COPY --from=build /build/target/release/examples/live_gate_dev_fixture_provision /usr/local/bin/live_gate_dev_fixture_provision
COPY --from=build /build/target/release/examples/live_gate_dev_bind_shutdown /usr/local/bin/live_gate_dev_bind_shutdown

set shell := ["bash", "-euo", "pipefail", "-c"]

ci:
  cargo fmt --all --check
  cargo check --all-features
  cargo clippy --all-targets --all-features -- -D warnings
  cargo clippy --all-targets --no-default-features -- -D warnings
  cargo nextest run --all-features

patch:
    cargo release patch --no-publish --execute

set shell := ["bash", "-cu"]

default:
    @just --list

build:
    cargo build --workspace
    cmake -S . -B build -G Ninja
    cmake --build build

test: build
    cargo test --workspace
    ctest --test-dir build --output-on-failure

test-bpf:
    cmake -S . -B build -G Ninja -DXPROBE_BUILD_BPF=ON
    cmake --build build --target xprobe-bpf

test-cupti:
    cmake -S . -B build -G Ninja -DXPROBE_BUILD_CUPTI=ON
    cmake --build build --target xprobe-cupti
    ctest --test-dir build --output-on-failure -R cupti

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

schemas:
    cargo run --package xprobe-protocol --bin generate-schemas

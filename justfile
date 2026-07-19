set shell := ["bash", "-cu"]

cuda_smoke_image := "nvcr.io/nvidia/cuda:13.3.0-base-ubuntu24.04@sha256:bcf7d05f0b13b9bbb86d9a4cd039d331894b8f1145ad009d1af75023bcd1dc5c"

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

gpu-smoke:
    docker run --rm --runtime=nvidia --gpus all {{cuda_smoke_image}} nvidia-smi --query-gpu=name,driver_version,compute_cap --format=csv,noheader

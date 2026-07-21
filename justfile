set shell := ["bash", "-cu"]

cuda_smoke_image := "nvcr.io/nvidia/cuda:13.3.0-base-ubuntu24.04@sha256:bcf7d05f0b13b9bbb86d9a4cd039d331894b8f1145ad009d1af75023bcd1dc5c"
cuda12_devel_image := "nvidia/cuda:12.9.1-devel-ubuntu24.04@sha256:020bc241a628776338f4d4053fed4c38f6f7f3d7eb5919fecb8de313bb8ba47c"
cuda12_min_devel_image := "nvidia/cuda:12.0.1-devel-ubuntu22.04@sha256:0632323ec456b33654d489f3ddd336f3b3ea1c87e6421a91a37f6768e659f08c"
cuda13_devel_image := "nvcr.io/nvidia/cuda:13.3.0-devel-ubuntu24.04@sha256:69e9e39eb8fe2cda271654a0f5eac2f1bb946b2fb9c460eb19c7c3c155f4e64e"

default:
    @just --list

build:
    cargo build --workspace
    cmake -S . -B build -G Ninja
    cmake --build build

test: build
    cargo test --workspace
    ctest --test-dir build --output-on-failure
    python3 tests/agent-contract/test_contract.py target/debug/xprobe

test-agent-contract: build
    python3 tests/agent-contract/test_contract.py target/debug/xprobe

test-bpf:
    cmake -S . -B build -G Ninja -DXPROBE_BUILD_BPF=ON
    cmake --build build --target xprobe-bpf

test-bpf-live: build
    python3 tests/integration/test_uprobe.py "{{cuda_smoke_image}}"

test-cupti:
    cmake -S . -B build -G Ninja -DXPROBE_BUILD_CUPTI=ON
    cmake --build build --target xprobe-cupti-smoke
    ctest --test-dir build --output-on-failure -R cupti

test-cupti-live: build
    python3 tests/integration/test_cupti.py "{{cuda13_devel_image}}" target/debug/xprobe

test-cupti-live-cuda12: build
    python3 tests/integration/test_cupti.py "{{cuda12_devel_image}}" target/debug/xprobe

test-cupti-live-cuda12-min: build
    python3 tests/integration/test_cuda12_compat.py "{{cuda12_devel_image}}" "{{cuda12_min_devel_image}}" target/debug/xprobe

test-injection-live: build
    python3 tests/integration/test_inject.py "{{cuda13_devel_image}}"

test-injection-live-cuda12: build
    python3 tests/integration/test_inject.py "{{cuda12_devel_image}}"

test-multisource-live: build
    python3 tests/integration/test_multisource.py "{{cuda13_devel_image}}" target/debug/xprobe

test-multisource-live-cuda12: build
    python3 tests/integration/test_multisource.py "{{cuda12_devel_image}}" target/debug/xprobe

benchmark-gpu:
    python3 benchmarks/cuda-callback/run.py "{{cuda13_devel_image}}"

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

schemas:
    cargo run --package xprobe-protocol --bin generate-schemas

package:
    scripts/package-release.sh

gpu-smoke:
    docker run --rm --runtime=nvidia --gpus all {{cuda_smoke_image}} nvidia-smi --query-gpu=name,driver_version,compute_cap --format=csv,noheader

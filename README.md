# perf-bench

## Prerequisites

### Environment Setup

```shell
sudo apt install linux-image-$(uname -r)-dbgsym
cd Downloads/
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 20
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-20 100
sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-20 100
sudo apt-get update && sudo apt-get install -y libpolly-20-dev libzstd-dev
cargo install --no-default-features bpf-linker
cargo install cargo-generate
cargo install bindgen-cli
cargo install --git https://github.com/aya-rs/aya -- aya-tool
```

```shell
sudo apt install linux-image-$(uname -r)-dbgsym
aya-tool generate trace_event_raw_sched_process_fork > perf-bench-ebpf/src/sched_process_fork.rs
aya-tool generate bpf_perf_event_data trace_event_raw_sched_switch task_struct > perf-bench-ebpf/src/bindings.rs
```

### CPU Sampling Results

```shell
RUSTFLAGS="-C force-frame-pointers=yes" cargo build
sudo RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/perf-bench --binary ~/workspace/personal/arkworks-examples/target/debug/arkworks-examples --function arkworks_examples::main
```

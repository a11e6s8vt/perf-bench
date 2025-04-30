/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
use std::env;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use aya_tool::generate::InputFile;
use which::which;

fn main() {
    cc::Build::new()
        .file("src/access.c")
        .include("src/vmlinux")
        .compile("access");
    println!("cargo:rerun-if-changed=src/vmlinux.h");
    println!("cargo:rerun-if-changed=src/access.c");

    let names: Vec<&str> = vec!["task_struct"];

    let bindings = bindgen::Builder::default()
        .header("src/vmlinux.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to output dir
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("vmlinux.rs"))
        .expect("Couldn't write bindings!");
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}

use libbpf_cargo::{Error, SkeletonBuilder};
use std::path::Path;

const BPF_SOURCE: &str = "./src/sweeper.bpf.c";
const SWEEPER_SKELETON: &str = "./src/sweeper.rs";

fn main() {
    let skel = Path::new(SWEEPER_SKELETON);
    match SkeletonBuilder::new()
        .source(BPF_SOURCE)
        .clang_args("-Wextra -Wall -Werror")
        .build_and_generate(skel)
    {
        Ok(_) => {}
        Err(err) => match err {
            Error::Build(msg) | Error::Generate(msg) => {
                panic!("{msg}");
            }
        },
    }

    println!("cargo:rerun-if-changed={BPF_SOURCE}");
}

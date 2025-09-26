use std::process::Command;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Debug, Parser)]
pub enum XtaskCommand {
    BuildEbpf(BuildEbpfOptions),
    Build(BuildOptions),
}

#[derive(Debug, Parser)]
pub struct BuildEbpfOptions {
    /// Set the endianness of the BPF target
    #[arg(default_value = "bpfel-unknown-none", long)]
    pub target: String,
    /// Build the release target
    #[arg(long)]
    pub release: bool,
}

#[derive(Debug, Parser)]
pub struct BuildOptions {
    /// Build the release target
    #[arg(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: BuildEbpfOptions) -> Result<(), anyhow::Error> {
    let dir = std::env::current_dir().unwrap();
    let target = format!("--target={}", opts.target);
    let mut args = vec![
        "+nightly",
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];

    if opts.release {
        args.push("--release")
    }

    let status = Command::new("cargo")
        .current_dir(&dir.join("probes"))
        .args(&args)
        .status()
        .expect("failed to build eBPF program");

    assert!(status.success());
    Ok(())
}

pub fn build(opts: BuildOptions) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");

    assert!(status.success());
    Ok(())
}

fn main() {
    let opts = Options::parse();

    use XtaskCommand::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf(opts),
        Build(opts) => build(opts),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}